const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');

const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  require('dotenv').config({ path: envPath });
  console.log('Successfully loaded .env file at:', envPath);
} else {
  console.log('No .env file found at:', envPath, 'using environment variables');
}

console.log('Loaded environment variables:', {
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID ? 'Set' : 'Not set',
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET ? 'Set' : 'Not set',
  GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
  JWT_SECRET: process.env.JWT_SECRET ? 'Set' : 'Not set',
  MONGO_URL: process.env.MONGO_URL ? 'Set' : 'Not set',
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: ['http://localhost:3000', 'https://convo-frontend.onrender.com','https://localhost:3000'],
    methods: ['GET', 'POST', 'GET'],
    credentials: true,
  },
});

// Serve static files from Uploads folder
app.use('/Uploads', express.static(path.join(__dirname, 'Uploads')));

// Create Uploads folder if it doesn't exist
const uploadDir = path.join(__dirname, 'Uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// MongoDB connection
mongoose.connect(process.env.MONGO_URL || 'mongodb://localhost/convo-app')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  googleId: String,
  email: String,
  username: { type: String, unique: true },
  password: String,
  profilePic: String,
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  sender: String,
  recipient: String,
  text: String,
  timestamp: { type: Date, default: Date.now },
  delivered: { type: Boolean, default: false },
  read: { type: Boolean, default: false },
  type: { type: String, default: 'text' },
  file: String,
  messageId: { type: String, unique: true, default: uuidv4 },
});
const Message = mongoose.model('Message', messageSchema);

const connectedUsers = new Map();

const storage = multer.diskStorage({
  destination: './Uploads/',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

// Passport Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      User.findOne({ googleId: profile.id }).then((user) => {
        if (!user) {
          user = new User({
            googleId: profile.id,
            email: profile.emails[0].value,
            username: profile.displayName,
          });
          user.save();
        }
        return done(null, user);
      });
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Middleware
app.use(cors({ 
    origin: ['http://localhost', 'https://convo-frontend:3000', 'https://convo-frontend.onrender.com'], 
    credentials: true 
  }));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URL })
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Profile picture endpoints
app.get('/api/user/profile-pic/:username', async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (user && user.profilePic) {
      res.json({ profilePic: user.profilePic });
    } else {
      res.json({ profilePic: null });
    }
  } catch (error) {
    console.error('Error fetching profile pic:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/user/update-profile-pic', upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const filePath = `/Uploads/${req.file.filename}`;
    const user = await User.findOneAndUpdate(
      { username: req.body.username },
      { profilePic: filePath },
      { new: true, runValidators: true }
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ filename: req.file.filename });
  } catch (error) {
    console.error('Error updating profile pic:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Unread messages endpoint
app.get('/api/messages/unread/:username', async (req, res) => {
  try {
    const username = req.params.username;
    const messages = await Message.aggregate([
      { $match: { recipient: username, read: false } },
      { $group: { _id: '$sender', count: { $sum: 1 } } },
    ]);
    const unread = {};
    messages.forEach((m) => (unread[m._id] = m.count));
    res.json(unread);
  } catch (error) {
    console.error('Error fetching unread messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Mark messages as read endpoint
app.post('/api/messages/mark-read/:username/:recipient', async (req, res) => {
  try {
    const { username, recipient } = req.params;
    await Message.updateMany(
      { sender: recipient, recipient: username, read: false },
      { $set: { read: true } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Authentication routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  if (req.user) {
    const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.redirect(`https://your-frontend.onrender.com/?token=${token}&username=${encodeURIComponent(req.user.username)}`);
  } else {
    res.redirect(`https://your-frontend.onrender.com`);
  }
});

app.post('/auth/register', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or username already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/authenticate', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, username: user.username });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find({}, 'username');
    res.json(users.map((user) => user.username));
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/search', async (req, res) => {
  try {
    const query = req.query.query || '';
    const users = await User.find(
      { username: { $regex: `^${query}`, $options: 'i' } },
      'username'
    ).lean();
    res.json(users.map((user) => user.username).filter((u) => u !== req.query.currentUser));
  } catch (error) {
    console.error('Error searching users:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/messages/count/:username', async (req, res) => {
  try {
    const user = req.params.username;
    const counts = {};
    const messages = await Message.find({
      $or: [{ sender: user }, { recipient: user }],
      read: false,
    }).lean();
    messages.forEach((msg) => {
      const otherUser = msg.sender === user ? msg.recipient : msg.sender;
      counts[otherUser] = (counts[otherUser] || 0) + 1;
    });
    res.json(counts);
  } catch (error) {
    console.error('Error fetching message counts:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/messages/:sender/:recipient', async (req, res) => {
  try {
    const messages = await Message.find({
      $or: [
        { sender: req.params.sender, recipient: req.params.recipient },
        { sender: req.params.recipient, recipient: req.params.sender },
      ],
    }).sort({ timestamp: 1 });
    await Message.updateMany(
      { recipient: req.params.recipient, sender: req.params.sender, read: false },
      { read: true }
    );
    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/messages/send', async (req, res) => {
  try {
    const { recipient, message, type, file, username, timestamp } = req.body;
    const newMessage = new Message({
      sender: username,
      recipient,
      text: message,
      timestamp: new Date(timestamp),
      type: type || 'text',
      file,
      delivered: connectedUsers.has(recipient),
    });
    await newMessage.save();
    const msg = {
      messageId: newMessage.messageId,
      username,
      text: message,
      timestamp: new Date(timestamp),
      type: type || 'text',
      file,
    };
    const recipientSocketId = connectedUsers.get(recipient);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('receiveMessage', msg);
      console.log(`Sent message ${msg.messageId} to ${recipient}`);
    }
    res.json(msg);
  } catch (error) {
    console.error('Error in /api/messages/send:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/messages/sendFile', upload.single('file'), async (req, res) => {
  try {
    const { recipient, username, timestamp } = req.body;
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const filePath = `/Uploads/${req.file.filename}`;
    const type = req.file.mimetype.startsWith('image') ? 'image' : 'document';
    const newMessage = new Message({
      sender: username,
      recipient,
      text: `Sent a ${type}`,
      timestamp: new Date(timestamp),
      type,
      file: filePath,
      delivered: connectedUsers.has(recipient),
    });
    await newMessage.save();
    const msg = {
      messageId: newMessage.messageId,
      username,
      text: `Sent a ${type}`,
      timestamp: new Date(timestamp),
      type,
      file: filePath,
    };
    const recipientSocketId = connectedUsers.get(recipient);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('receiveMessage', msg);
      console.log(`Sent message ${msg.messageId} to ${recipient}`);
    }
    res.json(msg);
  } catch (error) {
    console.error('Error in /api/messages/sendFile:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);
  socket.sentMessages = {};

  socket.on('registerUser', (username) => {
    connectedUsers.set(username, socket.id);
    socket.username = username;
    console.log('User registered:', username, 'with socket:', socket.id);
    io.emit('userStatus', { user: username, status: 'online' });
    io.emit('userListUpdate', Array.from(connectedUsers.keys()));
  });

  socket.on('sendMessage', async ({ recipient, message, type, file }) => {
    console.log('Attempting to send message to:', recipient, 'from:', socket.username);
    if (!connectedUsers.has(recipient)) {
      console.log('Recipient not connected:', recipient);
    }
    const recipientSocketId = connectedUsers.get(recipient);
    const newMessage = new Message({
      sender: socket.username,
      recipient,
      text: message,
      timestamp: new Date(),
      delivered: !!recipientSocketId,
      read: false,
      type: type || 'text',
      file,
    });
    try {
      await newMessage.save();
      const msg = {
        messageId: newMessage.messageId,
        username: socket.username,
        text: message,
        timestamp: new Date(),
        type: type || 'text',
        file,
      };
      if (recipientSocketId && !socket.sentMessages[msg.messageId]) {
        socket.sentMessages[msg.messageId] = true;
        io.to(recipientSocketId).emit('receiveMessage', msg);
        console.log(`Sent message ${msg.messageId} to ${recipient}`);
      }
      io.to(connectedUsers.get(socket.username)).emit('receiveMessage', msg);
    } catch (err) {
      console.error('Error saving message:', err);
    }
  });

  socket.on('typing', ({ recipient, username }) => {
    const recipientSocketId = connectedUsers.get(recipient);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('userTyping', { username });
    }
  });

  socket.on('stopTyping', ({ recipient }) => {
    const recipientSocketId = connectedUsers.get(recipient);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('userTyping', { username: '' });
    }
  });

  socket.on('disconnect', () => {
    for (let [user, sockId] of connectedUsers) {
      if (sockId === socket.id) {
        connectedUsers.delete(user);
        console.log('User disconnected:', user);
        io.emit('userStatus', { user, status: 'offline' });
        io.emit('userListUpdate', Array.from(connectedUsers.keys()));
        break;
      }
    }
  });
});

server.listen(process.env.PORT || 5000, () => console.log(`Server running on port ${process.env.PORT || 5000}`));