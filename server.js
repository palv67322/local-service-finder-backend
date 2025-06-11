const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'provider'], default: 'user' }
});

const serviceSchema = new mongoose.Schema({
  title: String,
  category: String,
  location: String,
  price: Number,
  provider: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const bookingSchema = new mongoose.Schema({
  serviceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Service' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  status: { type: String, default: 'pending' }
});

const User = mongoose.model('User', userSchema);
const Service = mongoose.model('Service', serviceSchema);
const Booking = mongoose.model('Booking', bookingSchema);

// Middleware to verify JWT
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// User Signup
app.post('/api/signup', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();
    const token = jwt.sign({ _id: user._id, role }, process.env.JWT_SECRET);
    res.status(201).json({ token, user });
  } catch (error) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ _id: user._id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token, user });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create Service (Provider only)
app.post('/api/services', auth, async (req, res) => {
  if (req.user.role !== 'provider') return res.status(403).json({ error: 'Not a provider' });
  const { title, category, location, price } = req.body;
  try {
    const service = new Service({ title, category, location, price, provider: req.user._id });
    await service.save();
    res.status(201).json(service);
  } catch (error) {
    res.status(400).json({ error: 'Failed to create service' });
  }
});

// Get All Services
app.get('/api/services', async (req, res) => {
  const { search, category, location } = req.query;
  let query = {};
  if (search) query.title = { $regex: search, $options: 'i' };
  if (category) query.category = category;
  if (location) query.location = { $regex: location, $options: 'i' };
  try {
    const services = await Service.find(query).populate('provider', 'name');
    res.json(services);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create Booking
app.post('/api/bookings', auth, async (req, res) => {
  const { serviceId } = req.body;
  try {
    const booking = new Booking({ serviceId, userId: req.user._id });
    await booking.save();
    res.status(201).json(booking);
  } catch (error) {
    res.status(400).json({ error: 'Failed to create booking' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));