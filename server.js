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
const cors = require('cors');

const app = express();
const server = http.createServer(app);

// Socket.IO configuration
const io = socketIo(server, {
  cors: {
    origin: ['http://localhost:3000', 'https://*.vercel.app'],
    credentials: true,
    methods: ['GET', 'POST'],
  },
});

// CORS middleware
app.use(
  cors({
    origin: ['http://localhost:3000', 'https://*.vercel.app'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// MongoDB connection and GridFS setup
let gridFSBucket;
mongoose
  .connect(process.env.MONGO_URL)
  .then(async () => {
    console.log('Connected to MongoDB');
    gridFSBucket = new GridFSBucket(mongoose.connection.db, { bucketName: 'Uploads' });
    await User.collection.createIndex({ username: 'text' });
    try {
      await User.collection.createIndex(
        { username: 1 },
        { unique: true, name: 'username_unique', collation: { locale: 'en', strength: 2 } }
      );
      console.log('Unique index created');
    } catch (err) {
      console.error('Failed to create unique index:', err.message);
    }
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String },
  profilePic: { type: String, default: null },
});

userSchema.pre('save', function (next) {
  if (this.username) this.username = this.username.toLowerCase();
  next();
});

const User = mongoose.model('User', userSchema);

// Message Schema
const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  recipient: { type: String, required: true },
  text: { type: String },
  type: { type: String, enum: ['text', 'image', 'document'], default: 'text' },
  file: { type: String },
  read: { type: Boolean, default: false },
  messageId: { type: String, unique: true },
  timestamp: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);

// Passport Configuration for Google OAuth
passport.serializeUser((user, done) => done(null, user.id));
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
          let username = profile.displayName.replace(/[^a-zA-Z0-9_]/g, '').toLowerCase().slice(0, 20) || 'user';
          let counter = 1;
          while (await User.findOne({ username })) {
            username = `${username}${counter}`;
            counter++;
          }
          user = new User({ email: profile.emails[0].value, username, password: null });
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
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only JPEG, PNG, and PDF files allowed'), false);
  },
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URL, collectionName: 'sessions' }),
  })
);
app.use(passport.initialize());
app.use(passport.session());

// JWT Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Socket.IO
io.on('connection', (socket) => {
  socket.on('registerUser', (username) => {
    socket.join(username.toLowerCase());
    socket.user = username.toLowerCase();
    io.emit('userStatus', { user: username.toLowerCase(), status: 'online' });
  });

  socket.on('sendMessage', async (data, callback) => {
    try {
      const { recipient, message, type, file, messageId, timestamp, username } = data;
      const msg = new Message({
        sender: username.toLowerCase(),
        recipient: recipient.toLowerCase(),
        text: message,
        type,
        file,
        messageId,
        timestamp: new Date(timestamp),
      });
      await msg.save();
      io.to(recipient.toLowerCase()).emit('receiveMessage', msg);
      io.to(username.toLowerCase()).emit('receiveMessage', msg);
      callback({ status: 'ok' });
    } catch (error) {
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
    if (socket.user) io.emit('userStatus', { user: socket.user, status: 'offline' });
  });
});

// Routes
app.post('/api/users/register', async (req, res) => {
  const { email, username, password } = req.body;
  try {
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'All fields required' });
    }
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ message: 'Username: 3-20 chars (letters, numbers, underscores)' });
    }
    if (!/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 chars' });
    }
    const existingUser = await User.findOne({ $or: [{ email }, { username: username.toLowerCase() }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, username: username.toLowerCase(), password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'Registered successfully' });
  } catch (error) {
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
    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });
    res.json({ token, username: user.username });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', { session: false }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user._id, username: req.user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.redirect(`${process.env.FRONTEND_URL}?token=${token}&username=${encodeURIComponent(req.user.username)}`);
  }
);

app.get('/api/users/search', authenticateJWT, async (req, res) => {
  const { query, currentUser } = req.query;
  try {
    const safeQuery = (query || '').replace(/[^a-zA-Z0-9_]/g, '');
    const users = safeQuery
      ? await User.find(
          { $text: { $search: safeQuery }, username: { $ne: currentUser.toLowerCase() } },
          { score: { $meta: 'textScore' } }
        )
          .sort({ score: { $meta: 'textScore' } })
          .select('username')
          .limit(20)
      : await User.find({ username: { $ne: currentUser.toLowerCase() } })
          .sort({ username: 1 })
          .select('username')
          .limit(20);
    res.json(users.map((u) => u.username));
  } catch (error) {
    res.status(500).json({ message: 'Failed to load contacts' });
  }
});

app.get('/api/users/profile-pic/:username', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username.toLowerCase() });
    res.json({ profilePic: user?.profilePic || null });
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch profile pic' });
  }
});

app.post('/api/users/uploadProfilePic', authenticateJWT, upload.single('file'), async (req, res) => {
  try {
    const { username } = req.body;
    const file = req.file;
    if (!file || !username) return res.status(400).json({ message: 'File and username required' });
    const uploadStream = gridFSBucket.openUploadStream(file.originalname);
    uploadStream.write(file.buffer);
    uploadStream.end();
    uploadStream.on('finish', async () => {
      await User.updateOne({ username: username.toLowerCase() }, { profilePic: uploadStream.id.toString() });
      res.json({ filename: uploadStream.id.toString() });
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to upload profile picture' });
  }
});

app.get('/api/messages/:currentUser/:recipient', authenticateJWT, async (req, res) => {
  try {
    const { currentUser, recipient } = req.params;
    const messages = await Message.find({
      $or: [
        { sender: currentUser.toLowerCase(), recipient: recipient.toLowerCase() },
        { sender: recipient.toLowerCase(), recipient: currentUser.toLowerCase() },
      ],
    }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.post('/api/messages/sendText', authenticateJWT, async (req, res) => {
  try {
    const { sender, recipient, text, timestamp } = req.body;
    const messageId = new mongoose.Types.ObjectId().toString();
    const message = new Message({
      sender: sender.toLowerCase(),
      recipient: recipient.toLowerCase(),
      text,
      type: 'text',
      messageId,
      timestamp: new Date(timestamp),
    });
    await message.save();
    res.json(message);
  } catch (error) {
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
        messageId,
        timestamp: new Date(timestamp),
      });
      await message.save();
      res.json(message);
    });
  } catch (error) {
    res.status(500).json({ message: 'Failed to send file' });
  }
});

app.get('/Uploads/:id', async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const downloadStream = gridFSBucket.openDownloadStream(fileId);
    downloadStream.on('error', () => res.status(404).json({ message: 'File not found' }));
    const file = await gridFSBucket.find({ _id: fileId }).next();
    if (file) {
      res.set('Content-Type', file.contentType || 'application/octet-stream');
      res.set('Content-Disposition', file.contentType.startsWith('image/') ? 'inline' : `attachment; filename="${file.filename}"`);
    }
    downloadStream.pipe(res);
  } catch (error) {
    res.status(500).json({ message: 'Failed to retrieve file' });
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
    res.status(500).json({ message: 'Failed to fetch unread messages' });
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
    res.status(500).json({ message: 'Failed to mark messages as read' });
  }
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));