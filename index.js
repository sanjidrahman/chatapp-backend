const express = require('express');
const http = require('http');
const socketIo = require('socket.io')
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const upload = require('./multer');
const session = require('express-session');
const auth = require('./auth')

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Middleware to parse JSON
app.use(express.json());
app.use(cors())
app.use('/file', express.static('public'));
app.use(session({
    secret: 'projectsecret',
    saveUninitialized: true,
    resave: false,
}))

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/chatapp')
    .then(() => console.log('DB Connected..!'))
    .catch((err) => console.log(err))

// Define schemas and models
const userSchema = new mongoose.Schema({
    username: String,
    email: { type: String, unique: true },
    password: String
});

const messageSchema = new mongoose.Schema({
    senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    message: { type: String },
    private: Boolean,
    file: {
        filename: String,
        mimetype: String,
        originalname: String,
    },
    createdAt: { type: Date, default: Date.now }
});

const User = require('./userModel');
const Message = mongoose.model('Message', messageSchema);

// Secret key for JWT
const JWT_SECRET = 'jwt_secret';

const securepassword = async (password) => {
    try {
        const securepassword = await bcrypt.hash(password, 10)
        return securepassword
    } catch (err) {
        console.log(err.message);
    }
}

// Register endpoint
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body
        const existingUser = await User.findOne({ email: email })

        if (existingUser) {
            return res.status(409).json({ message: 'User already exists' })
        }

        const spassword = await securepassword(password) // Hashing the password securely

        const newUser = new User({
            username,
            email: email,
            password: spassword,
        })
        const createdUser = await newUser.save()

        const payload = { id: createdUser._id, role: 'user' }; // Creating a payload for JWT token
        const token = jwt.sign({ payload }, JWT_SECRET); // Generating JWT token

        return res.status(201).json({ message: 'Success', token })

    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ message: 'Internal Server Error' })
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    try {

        const { email, password } = req.body
        const existingUser = await User.findOne({ email: email })

        if (!existingUser) {
            return res.status(404).json({ message: 'User not found, Please register!' })
        }

        const encpass = await bcrypt.compare(password, existingUser.password); // Comparing hashed passwords
        if (!encpass) {
            return res.status(401).json({ message: 'Email or Password incorrect' })
        }

        if (existingUser.isBlocked) {
            return res.status(403).json({ message: 'Access Denied' });
        }

        const payload = { id: existingUser._id, role: 'user' }; // Creating payload for JWT token
        const token = jwt.sign({ payload }, JWT_SECRET); // Generating JWT token

        return res.status(200).json({ message: 'Success', token })

    } catch (err) {
        res.status(500).json({ message: `Internal Server Error = ${err}` })
    }
});

app.get('/user', async (req, res) => {
    try {
        const users = await User.find({})
        res.status(200).json(users)
    } catch (err) {
        res.status(500).json({ message: `Internal Server Error = ${err}` })
    }
})

// Middleware to authenticate socket connections
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        return next(new Error('Authentication error'));
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return next(new Error('Authentication error'));
        }
        socket.user = decoded;
        next();
    });
});

const users = {};

// Socket.io connection handling
io.on('connection', async (socket) => {
    console.log('New client connected', socket.user.payload.id); // Log new client connection

    // Join room based on user ID
    // console.log(socket.id);
    socket.join(socket.user.payload.id);

    // Handle connection errors
    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
    });

    const senderData = await User.findOne({ _id: socket.user.payload.id })

    // Handle joining a group
    socket.on('joinGroup', (group) => {
        socket.join(group); // Join the specified group
        users[socket.user.payload.id] = { id: socket.user.payload.id, group }; // Store user's group info
        const joinMessage = `${senderData.username} has joined the group`;
        socket.broadcast.to(group).emit('userConnected', { message: joinMessage }); // Broadcast user connection message
        console.log(`Client ${senderData.username} joined group: ${group}`);
    });

    // Handle leaving a group
    socket.on('leaveGroup', (group) => {
        socket.leave(group); // Leave the specified group
        delete users[socket.user.payload.id]; // Remove user from stored groups
        const leaveMessage = `${senderData.username} has left the group`;
        socket.broadcast.to(group).emit('userDisconnected', { message: leaveMessage }); // Broadcast user disconnection message
        console.log(`Client ${senderData.username} left group: ${group}`);
    });

    // Handle group messages
    socket.on('groupMessage', async (data) => {
        const { group, message } = data;
        const senderId = socket.user.payload.id;
        const senderData = await User.findOne({ _id: senderId }); // Retrieve sender details
        const msg = new Message({
            message,
            senderId,
            private: false
        });
        const newMessage = await msg.save(); // Save new message to the database
        io.to(group).emit('groupMessage', { message: newMessage.message, senderId: senderData, createdAt: msg.createdAt }); // Broadcast group message
    });

    // Handle private messages
    socket.on('privateMessage', async (data) => {
        const { recipientId, message } = data;
        const senderId = socket.user.payload.id;
        const msg = new Message({
            senderId,
            recipientId,
            message,
            private: true,
        });
        const newMessage = await msg.save(); // Save new message to the database
        io.to(senderId).to(recipientId).emit('privateMessage', { message: newMessage.message, senderId, createdAt: newMessage.createdAt }); // Emit private message
    });

    // Fetch group message history
    socket.on('fetchGroupMessages', async ({ isPrivate }) => {
        const messages = await Message.find({
            private: isPrivate
        }).sort({ createdAt: 1 }).populate('senderId'); // Fetch messages and populate sender details
        socket.emit('messageHistory', messages); // Emit message history to the client
    });

    // Fetch private message history
    socket.on('fetchMessages', async ({ senderId, recipientId, isPrivate }) => {
        const messages = await Message.find({
            $and: [
                { senderId: { $in: [senderId, recipientId] } },
                { recipientId: { $in: [senderId, recipientId] } }
            ],
            private: isPrivate
        }).sort({ createdAt: 1 }); // Fetch messages between sender and recipient
        socket.emit('messageHistory', messages); // Emit message history to the client
    });

    // Handle client disconnection
    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

// Route for handling file uploads
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        const { senderId, recipientId, group } = req.body;
        if (!file) {
            return res.status(400).send('No file uploaded.');
        }

        // Check file size limit
        const fileSize = req.file.size;
        const maxSize = 10 * 1024 * 1024; // 10 MB
        if (fileSize > maxSize) {
            fs.unlinkSync(file.path);
            return res.status(400).send({ message: 'File size exceeds limit.' });
        }

        const senderData = await User.findOne({ _id: senderId }); // Retrieve sender details

        if (!group) {
            // Handling private file upload
            const newMessage = new Message({
                senderId,
                recipientId,
                file: {
                    filename: file.filename,
                    mimetype: file.mimetype,
                    originalname: file.originalname,
                },
                private: true,
            });

            const savedMessage = await newMessage.save(); // Save new message to the database

            // Emit private message to sender and recipient
            io.to(senderId).to(recipientId).emit('privateMessage', {
                _id: savedMessage._id,
                file: savedMessage.file,
                recipientId,
                senderId,
                createdAt: savedMessage.createdAt
            });
        } else {
            // Handling group file upload
            const newMessage = new Message({
                senderId,
                file: {
                    filename: file.filename,
                    mimetype: file.mimetype,
                    originalname: file.originalname,
                },
                private: false,
            });

            const savedMessage = await newMessage.save(); // Save new message to the database

            // Emit group message to all members of the group
            io.to(group).emit('groupMessage', {
                _id: savedMessage._id,
                file: savedMessage.file,
                senderId: senderData,
                createdAt: savedMessage.createdAt
            });
        }

        res.status(200).json({ message: 'File uploaded' });

    } catch (err) {
        res.status(500).json({ message: `Internal Server Error = ${err}` });
    }
});

// Route for serving files
app.get('/api/files/:id', auth, async (req, res) => {
    try {
        const message = await Message.findById(req.params.id);
        if (!message || !message.file.filename) {
            return res.status(404).send('File not found.');
        }

        const filePath = path.join(__dirname, './public/images', message.file.filename);

        // Set response headers for file download
        res.set({
            'Content-Type': message.file.mimetype,
            'Content-Disposition': `attachment; filename="${message.file.originalname}"`
        });

        // Stream file to response
        const readStream = fs.createReadStream(filePath);
        readStream.pipe(res);
    } catch (err) {
        console.log(err.message);
        res.status(500).send('Error retrieving file.');
    }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});