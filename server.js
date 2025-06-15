const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const Razorpay = require('razorpay');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const razorpay = new Razorpay({
  key_id: process.env.rzp_test_x1BNfcKz3XtHjz,
  key_secret: process.env.ZVCPvAhP8A1pxbVlB3OYHRkv
});

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ['user', 'provider'], default: 'user' },
  profile: { bio: String, phone: String, address: String }
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
  status: { type: String, default: 'pending' },
  date: Date,
  paymentId: String
});

const reviewSchema = new mongoose.Schema({
  serviceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Service' },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  text: String,
  rating: Number,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Service = mongoose.model('Service', serviceSchema);
const Booking = mongoose.model('Booking', bookingSchema);
const Review = mongoose.model('Review', reviewSchema);

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

app.post('/api/signup', async (req, res) => {
  const { name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();
    const token = jwt.sign({ _id: user._id, role }, process.env.JWT_SECRET);
    transporter.sendMail({
      to: email,
      subject: 'Welcome to Local Service Finder',
      text: `Hi ${name}, your account has been created successfully!`
    });
    res.status(201).json({ token, user });
  } catch (error) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

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

app.get('/api/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

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

app.get('/api/services/:id', async (req, res) => {
  try {
    const service = await Service.findById(req.params.id).populate('provider', 'name');
    res.json(service);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/services/provider', auth, async (req, res) => {
  try {
    const services = await Service.find({ provider: req.user._id });
    res.json(services);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/bookings', auth, async (req, res) => {
  const { serviceId, date } = req.body;
  try {
    const service = await Service.findById(serviceId);
    const order = await razorpay.orders.create({
      amount: service.price * 100,
      currency: 'INR'
    });
    const booking = new Booking({ serviceId, userId: req.user._id, date, paymentId: order.id });
    await booking.save();
    const user = await User.findById(req.user._id);
    transporter.sendMail({
      to: user.email,
      subject: 'Booking Confirmation',
      text: `Your booking for ${service.title} on ${date} has been placed. Order ID: ${order.id}`
    });
    res.status(201).json({ booking, orderId: order.id });
  } catch (error) {
    res.status(400).json({ error: 'Failed to create booking' });
  }
});

app.post('/api/payments/verify', async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const crypto = require('crypto');
  const generated_signature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');
  if (generated_signature === razorpay_signature) {
    res.json({ status: 'success' });
  } else {
    res.status(400).json({ error: 'Payment verification failed' });
  }
});

app.post('/api/reviews', auth, async (req, res) => {
  const { serviceId, text, rating } = req.body;
  try {
    const review = new Review({ serviceId, userId: req.user._id, text, rating });
    await review.save();
    const user = await User.findById(req.user._id);
    const service = await Service.findById(serviceId);
    transporter.sendMail({
      to: user.email,
      subject: 'Review Submitted',
      text: `Your review for ${service.title} has been submitted.`
    });
    res.status(201).json(review);
  } catch (error) {
    res.status(400).json({ error: 'Failed to submit review' });
  }
});

app.get('/api/reviews/:serviceId', async (req, res) => {
  try {
    const reviews = await Review.find({ serviceId: req.params.serviceId }).populate('user', 'name');
    res.json(reviews);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));