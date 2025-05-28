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
const winston = require('winston'); // Added for logging
const mongooseRetry = require('mongoose-retry'); // Added for MongoDB retry

const app = express();
const server = http.createServer(app);

// Logger setup
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

// Environment variable validation
const requiredEnvVars = [
  'MONGO_URL',
  'JWT_SECRET',
  'SESSION_SECRET',
  'GOOGLE_CLIENT_ID',
  'GOOGLE_CLIENT_SECRET',
  'GOOGLE_CALLBACK_URL',
  'FRONTEND_URL',
];
const missingVars = requiredEnvVars.filter((varName) => !process.env[varName]);
if (missingVars.length) {
  logger.error(`Missing environment variables: ${missingVars.join(', ')}`);
  process.exit(1);
}

// Socket.IO configuration
const allowedOrigins = [
  process.env.NODE_ENV === 'production'
    ? process.env.FRONTEND_URL
    : 'http://localhost:3000',
];
const io = socketIo(server, {
  cors: {
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn(`CORS blocked for origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST'],
  },
});

// CORS middleware
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        logger.warn(`CORS blocked for origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// MongoDB connection with retry
mongoose.set('plugin', mongooseRetry({ count: 5, backoff: 1000 }));
let gridFSBucket;
mongoose
  .connect(process.env.MONGO_URL)
  .then(async () => {
    logger.info('Connected to MongoDB');
    gridFSBucket = new GridFSBucket(mongoose.connection.db, { bucketName: 'Uploads' });
    await User.collection.createIndex({ username: 'text' });
    const indexes = await User.collection.indexes();
    const uniqueIndexExists = indexes.some((index) => index.name === 'username_unique');
    if (!uniqueIndexExists) {
      try {
        await User.collection.createIndex(
          { username: 1 },
          { unique: true, name: 'username_unique', collation: { locale: 'en', strength: 2 } }
        );
        logger.info('Unique index created on username');
      } catch (err) {
        logger.error('Failed to create unique index:', err.message);
      }
    }
    logger.info('MongoDB indexes verified');
  })
  .catch((err) => {
    logger.error('MongoDB connection error:', err.message);
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
  { timestamps: true, collation: { locale: 'en', strength: 2 } } // Case-insensitive queries
);

userSchema.pre('save', function (next) {
  if (this.username) {
    this.username = this.username.toLowerCase();
  }
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
    logger.error('Deserialize user error:', err.message);
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
          logger.info(`New Google user created: ${username}`);
        }
        done(null, user);
      } catch (err) {
        logger.error('Google auth error:', err.message);
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
    logger.warn('Authentication required: No token provided');
    return res.status(401).json({ message: 'Authentication required' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    logger.error('JWT verification error:', error.message);
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Socket.IO
io.on('connection', (socket) => {
  logger.info(`New client connected: ${socket.id}`);
  socket.on('registerUser', (username) => {
    socket.join(username.toLowerCase());
    socket.user = username.toLowerCase();
    io.emit('userStatus', { user: username.toLowerCase(), status: 'online' });
    logger.info(`User registered: ${username}`);
  });

  socket.on('sendMessage', async (data, callback) => {
    try {
      const { recipient, message, type, file, messageId, timestamp, username } = data;
      const existingMessage = await Message.findOne({ messageId });
      if (existingMessage) {
        logger.warn(`Duplicate messageId: ${messageId}`);
        return callback({ status: 'ok', message: 'Message already exists' });
      }
      const msg = new Message({
        sender: username.toLowerCase(),
        recipient: recipient.toLowerCase(),
        text: message,
        type,
        file,
        timestamp: new Date(timestamp),
        messageId,
      });
      await msg.save();
      io.to(recipient.toLowerCase()).emit('receiveMessage', msg.toObject());
      io.to(username.toLowerCase()).emit('receiveMessage', msg.toObject());
      logger.info(`Message sent from ${username} to ${recipient}`);
      callback({ status: 'ok' });
    } catch (error) {
      logger.error('Socket.IO sendMessage error:', error.message);
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
    logger.info(`Client disconnected: ${socket.id}`);
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
      const redirectUrl = new URL(process.env.FRONTEND_URL);
      redirectUrl.searchParams.set('token', token);
      redirectUrl.searchParams.set('username', encodeURIComponent(req.user.username));
      res.redirect(redirectUrl.toString());
      logger.info(`Google auth successful for user: ${req.user.username}`);
    } catch (error) {
      logger.error('Google auth callback error:', error.message);
      const redirectUrl = new URL(process.env.FRONTEND_URL);
      redirectUrl.searchParams.set('error', encodeURIComponent('Authentication failed'));
      res.redirect(redirectUrl.toString());
    }
  }
);

// Routes
app.post('/api/users/register', async (req, res) => {
  let { email, username, password } = req.body;
  username = username?.toLowerCase();
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
    logger.info(`User registered: ${username}`);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    logger.error('Registration error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password required' });
    }
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
    logger.info(`User logged in: ${user.username}`);
    res.json({ token, username: user.username });
  } catch (error) {
    logger.error('Login error:', error.message);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/search', authenticateJWT, async (req, res) => {
  const { query, currentUser, page = 1, limit = 20 } = req.query;
  if (!currentUser) {
    return res.status(400).json({ message: 'currentUser is required' });
  }
  try {
    const safeQuery = (query || '').replace(/[^a-zA-Z0-9_]/g, '').trim();
    const skip = (parseInt(page) - 1) * parseInt(limit);
    let users;
    if (!safeQuery) {
      users = await User.find({
        username: { $ne: currentUser.toLowerCase() },
      })
        .collation({ locale: 'en', strength: 2 })
        .sort({ username: 1 })
        .skip(skip)
        .limit(parseInt(limit))
        .select('username');
    } else {
      users = await User.find(
        {
          $text: { $search: safeQuery },
          username: { $ne: currentUser.toLowerCase() },
        },
        { score: { $meta: 'textScore' } }
      )
        .sort({ score: { $meta: 'textScore' }, username: 1 })
        .skip(skip)
        .limit(parseInt(limit))
        .select('username');
    }
    res.json(users.map((user) => user.username));
  } catch (error) {
    logger.error('Search users error:', error.message);
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
    logger.error('Unread messages error:', error.message);
    res.status(500).json({ message: 'Failed to fetch unread messages' });
  }
});

app.get('/api/users/profile-pic/:username', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne(
      { username: req.params.username.toLowerCase() },
      null,
      { collation: { locale: 'en', strength: 2 } }
    );
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ profilePic: user.profilePic || null });
  } catch (error) {
    logger.error('Profile pic error:', error.message);
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
    uploadStream.on('error', (err) => {
      logger.error('Profile pic upload stream error:', err.message);
      res.status(500).json({ message: 'Failed to upload file' });
    });
    uploadStream.write(file.buffer);
    uploadStream.end();
    uploadStream.on('finish', async () => {
      const user = await User.findOne({ username: username.toLowerCase() });
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      const oldProfilePic = user.profilePic;
      if (oldProfilePic) {
        try {
          await gridFSBucket.delete(new mongoose.Types.ObjectId(oldProfilePic));
          logger.info(`Deleted old profile pic: ${oldProfilePic}`);
        } catch (err) {
          logger.warn('Failed to delete old profile pic:', err.message);
        }
      }
      user.profilePic = uploadStream.id.toString();
      await user.save();
      logger.info(`Profile pic updated for user: ${username}`);
      res.json({ filename: uploadStream.id.toString() });
    });
  } catch (error) {
    logger.error('Profile pic upload error:', error.message);
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
      .collation({ locale: 'en', strength: 2 })
      .sort({ timestamp: 1 })
      .skip((parseInt(page) - 1) * parseInt(limit))
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
    logger.error('Fetch messages error:', error.message);
    res.status(500).json({ message: 'Failed to fetch messages' });
  }
});

app.post('/api/messages/mark-read/:currentUser/:recipient', authenticateJWT, async (req, res) => {
  try {
    const { currentUser, recipient } = req.params;
    await Message.updateMany(
      { sender: recipient.toLowerCase(), recipient: currentUser.toLowerCase(), read: false },
      { read: true },
      { collation: { locale: 'en', strength: 2 } }
    );
    io.to(currentUser.toLowerCase()).emit('messagesRead', { recipient: recipient.toLowerCase() });
    logger.info(`Messages marked read for ${currentUser} from ${recipient}`);
    res.json({ message: 'Messages marked as read' });
  } catch (error) {
    logger.error('Mark read error:', error.message);
    res.status(500).json({ message: 'Failed to mark messages as read' });
  }
});

app.post('/api/messages/sendText', authenticateJWT, async (req, res) => {
  try {
    const { sender, recipient, text, timestamp } = req.body;
    if (!sender || !recipient || !text || !timestamp) {
      return res.status(400).json({ message: 'Missing required fields' });
    }
    const senderExists = await User.findOne(
      { username: sender.toLowerCase() },
      null,
      { collation: { locale: 'en', strength: 2 } }
    );
    const recipientExists = await User.findOne(
      { username: recipient.toLowerCase() },
      null,
      { collation: { locale: 'en', strength: 2 } }
    );
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
    logger.info(`Text message sent from ${sender} to ${recipient}`);
    res.json({
      messageId: message.messageId,
      sender: message.sender,
      recipient: message.recipient,
      text: message.text,
      type: message.type,
      timestamp: message.timestamp,
    });
  } catch (error) {
    logger.error('Text message save error:', error.message);
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
    const senderExists = await User.findOne(
      { username: username.toLowerCase() },
      null,
      { collation: { locale: 'en', strength: 2 } }
    );
    const recipientExists = await User.findOne(
      { username: recipient.toLowerCase() },
      null,
      { collation: { locale: 'en', strength: 2 } }
    );
    if (!senderExists || !recipientExists) {
      return res.status(400).json({ message: 'Invalid sender or recipient' });
    }
    const uploadStream = gridFSBucket.openUploadStream(file.originalname);
    uploadStream.on('error', (err) => {
      logger.error('File upload stream error:', err.message);
      res.status(500).json({ message: 'Failed to upload file' });
    });
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
      logger.info(`File message sent from ${username} to ${recipient}`);
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
    logger.error('File upload error:', error.message);
    res.status(500).json({ message: 'Failed to send file' });
  }
});

app.get('/Uploads/:id', async (req, res) => {
  try {
    const fileId = new mongoose.Types.ObjectId(req.params.id);
    const downloadStream = gridFSBucket.openDownloadStream(fileId);
    downloadStream.on('error', () => {
      logger.warn(`File not found: ${req.params.id}`);
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
    logger.error('File download error:', error.message);
    res.status(500).json({ message: 'Failed to retrieve file' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(`Unhandled error: ${err.message}`, { stack: err.stack });
  const status = err.status || 500;
  const message = process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message;
  res.status(status).json({ message });
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});