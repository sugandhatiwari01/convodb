const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const { GridFSBucket } = require('mongodb');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const socketIo = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);

// Define allowed origins for CORS
const allowedOrigins = [
  'http://localhost:3000',
  'https://convo-frontend.vercel.app',
  'https://convo-frontend.onrender.com',
];

// Socket.IO configuration
const io = socketIo(server, {
  cors: {
    origin: allowedOrigins,
    credentials: true,
    methods: ['GET', 'POST'],
  },
});

// MongoDB connection and GridFS setup
let gridFSBucket;
mongoose
  .connect(process.env.MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('Connected to MongoDB');
    gridFSBucket = new GridFSBucket(mongoose.connection.db, { bucketName: 'Uploads' });
  })
  .catch((err) => console.error('MongoDB connection error:', err));

// Define Mongoose Models Inline
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String },
  profilePic: { type: String, default: null },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },
  recipient: { type: String, required: true },
  text: { type: String },
  type: { type: String, enum: ['text', 'image', 'document'], default: 'text' },
  file: { type: String },
  read: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
});

const Message = mongoose.model('Message', messageSchema);

// Passport Configuration Inline
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
          user = new User({
            email: profile.emails[0].value,
            username: profile.displayName.replace(/\s/g, '').toLowerCase(),
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
const upload = multer({ storage });

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// JWT Middleware
const authenticateJWT = (req, res, next) => {
  const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
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
  console.log('New client connected:', socket.id);
  socket.on('registerUser', (username) => {
    socket.join(username.toLowerCase());
    socket.user = username;
    io.emit('userStatus', { user: username, status: 'online' });
  });
  socket.on('sendMessage', ({ recipient, message, type, file }) => {
    const msg = { username: socket.user, message, type, file, messageId: Date.now().toString() };
    io.to(recipient.toLowerCase()).emit('receiveMessage', msg);
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

// Routes
app.post('/api/auth/register', async (req, res) => {
  let { email, username, password } = req.body;
  username = username.toLowerCase();
  try {
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'All fields required' });
    }
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ message: 'Invalid username' });
    }
    if (!/^[\w-.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
      return res.status(400).json({ message: 'Invalid email' });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password too short' });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or username exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, username, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
    res.json({ token, username: user.username });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/search', authenticateJWT, async (req, res) => {
  const { query, currentUser } = req.query;
  if (!currentUser) {
    return res.status(400).json({ message: 'currentUser is required' });
  }
  try {
    const regex = new RegExp(query || '', 'i');
    const users = await User.find({
      username: { $regex: regex },
      username: { $ne: currentUser.toLowerCase() },
    }).select('username');
    const usernames = users.map((user) => user.username);
    res.json(usernames);
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
    console.error('Unread messages error:', error);
    res.status(500).json({ message: 'Failed to fetch unread messages' });
  }
});

app.get('/api/user/profile-pic/:username', authenticateJWT, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username.toLowerCase() });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ profilePic: user.profilePic || null });
  } catch (error) {
    console.error('Profile pic error:', error);
    res.status(500).json({ message: 'Failed to fetch profile pic' });
  }
});

app.post('/api/user/update-profile-pic', authenticateJWT, upload.single('profilePic'), async (req, res) => {
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
      await User.updateOne(
        { username: username.toLowerCase() },
        { profilePic: uploadStream.id.toString() }
      );
      res.json({ filename: uploadStream.id.toString() });
    });
  } catch (error) {
    console.error('Profile pic upload error:', error);
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
    res.json(
      messages.map((msg) => ({
        messageId: msg._id.toString(),
        sender: msg.sender,
        text: msg.text,
        timestamp: msg.timestamp,
        type: msg.type,
        file: msg.file,
      }))
    );
  } catch (error) {
    console.error('Fetch messages error:', error);
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
    res.json({ message: 'Messages marked as read' });
  } catch (error) {
    console.error('Mark read error:', error);
    res.status(500).json({ message: 'Failed to mark messages as read' });
  }
});

app.post('/api/messages/sendFile', authenticateJWT, upload.single('file'), async (req, res) => {
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
      const message = new Message({
        sender: username.toLowerCase(),
        recipient: recipient.toLowerCase(),
        type: file.mimetype.startsWith('image/') ? 'image' : 'document',
        file: uploadStream.id.toString(),
        timestamp: new Date(timestamp),
      });
      await message.save();
      res.json({
        messageId: message._id.toString(),
        sender: username,
        recipient,
        type: message.type,
        file: message.file,
        timestamp: message.timestamp,
      });
    });
  } catch (error) {
    console.error('File upload error:', error);
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
    downloadStream.pipe(res);
  } catch (error) {
    console.error('File download error:', error);
    res.status(500).json({ message: 'Failed to retrieve file' });
  }
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));