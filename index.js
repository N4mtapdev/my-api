const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI)
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const orderSchema = new mongoose.Schema({
    platform: { type: String, required: true },
    service: { type: String, required: true },
    link: { type: String, required: true },
    quantity: { type: Number, required: true },
    note: { type: String, default: '' },
    status: { type: String, default: 'pending' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
});

const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);

const authMiddleware = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'No token' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: 'Missing fields' });
        const existingUser = await User.findOne({ username });
        if (existingUser) return res.status(400).json({ message: 'Username taken' });
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/boost', authMiddleware, async (req, res) => {
    try {
        const { platform, service, link, quantity, note } = req.body;
        if (!platform || !service || !link || !quantity) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        if (quantity < 10 || quantity > 10000) {
            return res.status(400).json({ message: 'Quantity must be between 10 and 10,000' });
        }
        const order = new Order({
            platform, service, link, quantity, note, userId: req.user.userId
        });
        await order.save();
        res.status(201).json({ status: 'success', orderId: order._id, message: 'Order created' });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/orders', authMiddleware, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.user.userId });
        res.status(200).json(orders);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
