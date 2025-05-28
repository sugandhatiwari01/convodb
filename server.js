const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { GridFSBucket } = require('mongodb');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const socketIo = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);

// Socket.IO configuration
const io = socketIo(server, {
  cors: {
    origin: (origin, callback) => {
      // Allow all *.vercel.app origins and localhost
      if (!origin || origin.match(/\.vercel\.app$/) || origin === 'http://localhost:3000') {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST'],
  },
});

// MongoDB connection and GridFS setup
let gridFSBucket;
mongoose
  .connect(process.env.MONGO_URL)
  .then(async () => {
    console.log('Connected to MongoDB');
    gridFSBucket = new GridFSBucket(mongoose.connection.db, { bucketName: 'Uploads' });
    // Create text index for search
    await User.collection.createIndex({ username: 'text' });
    // Check for existing unique index
    const indexes = await User.collection.indexes();
    const uniqueIndexExists = indexes.some((index) => index.name === 'username_unique');
    if (!uniqueIndexExists) {
      try {
        await User.collection.createIndex(
          { username: 1 },
          { unique: true, name: 'username_unique', collation: { locale: 'en', strength: 2 } }
        );
        console.log('Unique index created successfully');
      } catch (err) {
        console.error('Failed to create unique index:', err.message);
      }
    }
    console.log('Indexes verified');
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String },
    profilePic: { type: String, default: null },
  },
  { timestamps: true }
);

// Normalize username to lowercase before saving
userSchema.pre('save', function (next) {
  if (this.username) {
    this.username = this.username.toLowerCase();
  }
  next();
});

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  recipient: { type: String, required: true },
  text: { type: String },
  type: { type: String, enum: ['text', 'image', 'document'], default: 'text' },
  file: { type: String },
  read: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
  messageId: { type: String, unique: true },
});

const Message = mongoose.model('Message', messageSchema);

// Passport Configuration
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (!user) {
          let username =
            profile.displayName.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase().slice(0, 20) || 'user';
          let baseUsername = username;
          let counter = 1;
          while (await User.findOne({ username })) {
            username = `${baseUsername}${counter}`;
            counter++;
          }
          user = new User({
            email: profile.emails[0].value,
            username,
            password: null,
          });
          await user.save();
        }
        done(null, user);
      } catch (err) {
        done(err, null);
      }
    }
  )
);

// Multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Only JPEG, PNG, and PDF files are allowed'), false);
    }
  },
});

// Middleware
// In server.js
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && (origin.match(/\.vercel\.app$/) || origin === 'http://localhost:3000')) {
    console.log('CORS allowing origin:', origin); // Debug log
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  }
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URL,
      collectionName: 'sessions',
      ttl: 24 * 60 * 60,
    }),
  })
);
app.use(passport.initialize());
app.use(passport.session());

// JWT Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('JWT error:', error.message);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Socket.IO
io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  socket.on('registerUser', (username) => {
    socket.join(username.toLowerCase());
    socket.user = username.toLowerCase();
    io.emit('userStatus', { user: username.toLowerCase(), status: 'online' });
  });

  socket.on('sendMessage', async (data, callback) => {
    try {
      const { recipient, message, type, file, messageId, timestamp, username } = data;
      const existingMessage = await Message.findOne({ messageId });
      if (existingMessage) {
        return callback({ status: 'ok', message: 'Message already exists' });
      }
      const msg = {
        sender: username.toLowerCase(),
        recipient: recipient.toLowerCase(),
        text: message,
        type,
        file,
        timestamp: new Date(timestamp),
        messageId,
      };
      await new Message(msg).save();
      io.to(recipient.toLowerCase()).emit('receiveMessage', msg);
      io.to(username.toLowerCase()).emit('receiveMessage', msg);
      callback({ status: 'ok' });
    } catch (error) {
      console.error('Socket.IO sendMessage error:', error.message);
      callback({ status: 'error', message: 'Failed to send message' });
    }
  });

  socket.on('typing', ({ recipient, username }) => {
    io.to(recipient.toLowerCase()).emit('userTyping', { username });
  });

  socket.on('stopTyping', ({ recipient }) => {
    io.to(recipient.toLowerCase()).emit('userTyping', {});
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
    if (socket.user) {
      io.emit('userStatus', { user: socket.user, status: 'offline' });
    }
  });
});

// Google Auth Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    try {
      const token = jwt.sign(
        { userId: req.user._id, username: req.user.username },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.redirect(
        `${process.env.FRONTEND_URL}?token=${token}&username=${encodeURIComponent(req.user.username)}`
      );
    } catch (error) {
      console.error('Google auth callback error:', error.message);
      res.redirect(
        `${process.env.FRONTEND_URL}?error=${encodeURIComponent('Authentication failed')}`
      );
    }
  }
);

// Routes
app.post('/api/users/register', async (req, res) => {
  let { email, username, password } = req.body;
  username = username.toLowerCase();
  try {
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'All fields required' });
    }
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({
        message: 'Username must be 3-20 characters (letters, numbers, underscores)',
      });
    }
    if (!/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, username, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !user.password) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token, username: user.username });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/search', authenticateJWT, async (req, res) => {
  const { query, currentUser } = req.query;
  if (!currentUser) {
    return res.status(400).json({ message: 'currentUser is required' });
  }
  try {
    const safeQuery = (query || '').replace(/[^a-zA-Z0-9_]/g, '').trim();
    if (!safeQuery) {
      const users = await User.find({
        username: { $ne: currentUser.toLowerCase() },
      })
        .collation({ locale: 'en', strength: 2 })
        .sort({ username: 1 })
        .select('username')
        .limit(20);
      return res.json(users.map((user) => user.username));
    }
    const users = await User.find(
      {
        $text: { $search: safeQuery },
        username: { $ne: currentUser.toLowerCase() },
      },
      { score: { $meta: 'textScore' } }
    )
      .sort({ score: { $meta: 'textScore' }, username: 1 })
      .select('username')
      .limit(20);
    res.json(users.map((user) => user.username));
  } catch (error) {
    console.error('Search users error:', error);
    res.status(500).json({ message: 'Failed to load contacts' });
  }
});

app.get('/api/messages/unread/:username', authenticateJWT, async (req, res) => {
  try {
    const { username } = req.params;
    const unreadCounts = await Message.aggregate([
      { $match: { recipient: username.toLowerCase(), read: false } },
      { $group: { _id: '$sender', count: { $sum: 1 } } },
    ]);
    const unreadMessages = {};
    unreadCounts.forEach(({ _id, count }) => {
      unreadMessages[_id] = count;
    });
    res.json(unreadMessages);
  } catch (error) {
    console.error('Unread messages error:', error.message);
    res.status(500).json({ message: 'Failed to fetch unread messages' });
  }
});

app.get('/api/users/profile-pic/:username', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username.toLowerCase() });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ profilePic: user.profilePic || null });
  } catch (error) {
    console.error('Profile pic error:', error.message);
    res.status(500).json({ message: 'Failed to fetch profile pic' });
  }
});

app.post('/api/users/uploadProfilePic', authenticateJWT, upload.single('file'), async (req, res) => {
  try {
    const { username } = req.body;
    const file = req.file;
    if (!file || !username) {
      return res.status(400).json({ message: 'File and username are required' });
    }
    const uploadStream = gridFSBucket.openUploadStream(file.originalname);
    uploadStream.write(file.buffer);
    uploadStream.end();
    uploadStream.on('finish', async () => {
      const oldProfilePic = (await User.findOne({ username: username.toLowerCase() })).profilePic;
      if (oldProfilePic) {
        try {
          await gridFSBucket.delete(new mongoose.Types.ObjectId(oldProfilePic));
        } catch (err) {
          console.warn('Failed to delete old profile pic:', err.message);
        }
      }
      await User.updateOne(
        { username: username.toLowerCase() },
        { profilePic: uploadStream.id.toString() }
      );
      res.json({ filename: uploadStream.id.toString() });
    });
  } catch (error) {
    console.error('Profile pic upload error:', error.message);
    res.status(500).json({ message: 'Failed to upload profile picture' });
  }
});

app.get('/api/messages/:currentUser/:recipient', authenticateJWT, async (req, res) => {
  try {
    const { currentUser, recipient } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const messages = await Message.find({
      $or: [
        { sender: currentUser.toLowerCase(), recipient: recipient.toLowerCase() },
        { sender: recipient.toLowerCase(), recipient: currentUser.toLowerCase() },
      ],
    })
      .sort({ timestamp: 1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    res.json(
      messages.map((msg) => ({
        messageId: msg.messageId,
        sender: msg.sender,
        text: msg.text,
        timestamp: msg.timestamp,
        type: msg.type,
        file: msg.file,
      }))
    );
  } catch (error) {
    console.error('Fetch messages error:', error.message);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.post('/api/messages/mark-read/:currentUser/:recipient', authenticateJWT, async (req, res) => {
  try {
    const { currentUser, recipient } = req.params;
    await Message.updateMany(
      { sender: recipient.toLowerCase(), recipient: currentUser.toLowerCase(), read: false },
      { read: true }
    );
    io.to(currentUser.toLowerCase()).emit('messagesRead', { recipient: recipient.toLowerCase() });
    res.json({ message: 'Messages marked as read' });
  } catch (error) {
    console.error('Mark read error:', error.message);
    res.status(500).json({ message: 'Failed to mark messages as read' });
  }
});

app.post('/api/messages/sendText', authenticateJWT, async (req, res) => {
  try {
    const { sender, recipient, text, timestamp } = req.body;
    if (!sender || !recipient || !text || !timestamp) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const senderExists = await User.findOne({ username: sender.toLowerCase() });
    const recipientExists = await User.findOne({ username: recipient.toLowerCase() });
    if (!senderExists || !recipientExists) {
      return res.status(400).json({ message: 'Invalid sender or recipient' });
    }
    const messageId = new mongoose.Types.ObjectId().toString();
    const message = new Message({
      sender: sender.toLowerCase(),
      recipient: recipient.toLowerCase(),
      text,
      type: 'text',
      timestamp: new Date(timestamp),
      messageId,
    });
    await message.save();
    res.json({
      messageId: message.messageId,
      sender: message.sender,
      recipient: message.recipient,
      text: message.text,
      type: message.type,
      timestamp: message.timestamp,
    });
  } catch (error) {
    console.error('Text message save error:', error.message);
    res.status(500).json({ message: 'Failed to send message' });
  }
});

app.post('/api/messages/uploadFile', authenticateJWT, upload.single('file'), async (req, res) => {
  try {
    const { recipient, username, timestamp } = req.body;
    const file = req.file;
    if (!file || !recipient || !username || !timestamp) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const senderExists = await User.findOne({ username: username.toLowerCase() });
    const recipientExists = await User.findOne({ username: recipient.toLowerCase() });
    if (!senderExists || !recipientExists) {
      return res.status(400).json({ message: 'Invalid sender or recipient' });
    }
    const uploadStream = gridFSBucket.openUploadStream(file.originalname);
    uploadStream.write(file.buffer);
    uploadStream.end();
    uploadStream.on('finish', async () => {
      const messageId = new mongoose.Types.ObjectId().toString();
      const message = new Message({
        sender: username.toLowerCase(),
        recipient: recipient.toLowerCase(),
        type: file.mimetype.startsWith('image/') ? 'image' : 'document',
        file: uploadStream.id.toString(),
        timestamp: new Date(timestamp),
        messageId,
      });
      await message.save();
      res.json({
        messageId: message.messageId,
        sender: username,
        recipient,
        type: message.type,
        file: message.file,
        timestamp: message.timestamp,
      });
    });
  } catch (error) {
    console.error('File upload error:', error.message);
    res.status(500).json({ message: 'Failed to send file' });
  }
});

app.get('/Uploads/:id', async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const downloadStream = gridFSBucket.openDownloadStream(fileId);
    downloadStream.on('error', () => {
      res.status(404).json({ message: 'File not found' });
    });
    const file = await gridFSBucket.find({ _id: fileId }).next();
    if (file) {
      res.set('Content-Type', file.contentType || 'application/octet-stream');
      if (file.contentType.startsWith('image/')) {
        res.set('Content-Disposition', 'inline');
      } else {
        res.set('Content-Disposition', `attachment; filename="${file.filename}"`);
      }
    }
    downloadStream.pipe(res);
  } catch (error) {
    console.error('File download error:', error.message);
    res.status(500).json({ message: 'Failed to retrieve file' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  const status = err.status || 500;
  const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;
  res.status(status).json({ message });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));