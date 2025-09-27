import dotenv from 'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();

app.use(cors());
app.use(express.json());

// === Prevent repeated DB connection ===
let isConnected;
async function connectDB() {
  if (isConnected) return;
  await mongoose.connect(process.env.Database_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  isConnected = true;
  console.log('MongoDB Connected');
}


connectDB()

// === PRESALE END DATE/TIME MODEL ===
const presaleEndSchema = new mongoose.Schema({
  endDateTime: { type: Date, required: true }
}, { timestamps: true });

const PresaleEnd = mongoose.models.PresaleEnd || mongoose.model("PresaleEnd", presaleEndSchema);


// === PROGRESS BAR VALUE MODEL ===
const progressBarSchema = new mongoose.Schema({
  value: { type: Number, required: true } // store percentage or number of tokens
}, { timestamps: true });

const ProgressBar = mongoose.models.ProgressBar || mongoose.model("ProgressBar", progressBarSchema);



const adminSchema = new mongoose.Schema({
  password: String,
  initialized: { type: Boolean, default: false },
});

const Admin = mongoose.models.Admin || mongoose.model("Admin", adminSchema);

const walletAddressSchema = new mongoose.Schema({
  address: { type: String, required: true }
}, { timestamps: true });

const WalletAddress = mongoose.models.WalletAddress || mongoose.model("WalletAddress", walletAddressSchema);


// === Middleware ===
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  try {
    jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    res.status(403).json({ message: 'Invalid token' });
  }
};


async function initializeAdmin() {
  await connectDB();

  try {
    const existingAdmin = await Admin.findOne();
    if (existingAdmin && existingAdmin.initialized) return;

    const adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminPassword || adminPassword.length < 8) {
      console.error('ADMIN_PASSWORD must be set and at least 8 characters.');
      return;
    }

    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    if (existingAdmin) {
      existingAdmin.password = hashedPassword;
      existingAdmin.initialized = true;
      await existingAdmin.save();
    } else {
      await new Admin({ password: hashedPassword, initialized: true }).save();
    }
  } catch (err) {
    console.error('Error initializing admin:', err.message);
  }
}


app.post('/api/authenticate', async (req, res) => {
  await connectDB();
  const { password } = req.body;
  if (!password || password.length < 8)
    return res.status(400).json({ message: 'Password must be at least 8 characters' });

  try {
    const admin = await Admin.findOne();
    if (!admin || !admin.initialized)
      return res.status(401).json({ message: 'Admin account not initialized' });

    const match = await bcrypt.compare(password, admin.password);
    if (match) {
      const token = jwt.sign({ admin: true }, process.env.JWT_SECRET, { expiresIn: '1h' });
      return res.json({ token });
    } else {
      return res.status(401).json({ message: 'Invalid password' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/verify-token', authenticateJWT, (req, res) => {
  res.status(200).json({ message: 'Token valid' });
});

// ADD Presale End Date/Time (admin protected)
app.post('/api/presale-end', authenticateJWT, async (req, res) => {
  await connectDB();
  const { endDateTime } = req.body;
  if (!endDateTime) return res.status(400).json({ message: 'endDateTime is required' });

  try {
    // either update existing or create new
    let record = await PresaleEnd.findOne();
    if (record) {
      record.endDateTime = new Date(endDateTime);
      await record.save();
    } else {
      record = await PresaleEnd.create({ endDateTime: new Date(endDateTime) });
    }
    res.json({ message: 'Presale end date saved', data: record });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET Presale End Date/Time
app.get('/api/presale-end', async (req, res) => {
  await connectDB();
  try {
    const record = await PresaleEnd.findOne().sort({ createdAt: -1 });
    res.json(record || { message: 'No presale end date set yet' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


// ADD/UPDATE Progress Bar Value (admin protected)
// app.post('/api/progress-bar', authenticateJWT, async (req, res) => {
//   await connectDB();
//   const { value } = req.body;
//   if (value === undefined) return res.status(400).json({ message: 'value is required' });

//   try {
//     let record = await ProgressBar.findOne();
//     if (record) {
//       record.value = value;
//       await record.save();
//     } else {
//       record = await ProgressBar.create({ value });
//     }
//     res.json({ message: 'Progress bar value saved', data: record });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ message: 'Server error' });
//   }
// });

// ADD/UPDATE Progress Bar Value (admin protected)
app.post('/api/progress-bar', authenticateJWT, async (req, res) => {
  await connectDB();
  let { value } = req.body;

  // Validate presence
  if (value === undefined) {
    return res.status(400).json({ message: 'value is required' });
  }

  // Clamp value between 0 and 100
  value = Math.max(0, Math.min(Number(value), 100));

  try {
    let record = await ProgressBar.findOne();
    if (record) {
      record.value = value;
      await record.save();
    } else {
      record = await ProgressBar.create({ value });
    }
    res.json({ message: 'Progress bar value saved', data: record });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});


// GET Progress Bar Value
app.get('/api/progress-bar', async (req, res) => {
  await connectDB();
  try {
    const record = await ProgressBar.findOne().sort({ createdAt: -1 });
    res.json(record || { message: 'No progress bar value set yet' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ADD Wallet Address (allow multiple)
// ADD Wallet Address (no duplicates)
app.post('/api/wallet-address', async (req, res) => {
  await connectDB();
  const { address } = req.body;

  if (!address) return res.status(400).json({ message: 'Address is required' });

  try {
    // Always store lowercase
    const lowerAddr = address.toLowerCase();

    // check first
    const existing = await WalletAddress.findOne({ address: lowerAddr });
    if (existing) {
      return res.status(409).json({ message: 'Address already exists', data: existing });
    }

    const record = await WalletAddress.create({ address: lowerAddr });
    res.json({ message: 'Wallet address saved', data: record });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET All Wallet Addresses
app.get('/api/wallet-address', async (req, res) => {
  await connectDB();
  try {
    const records = await WalletAddress.find({}).sort({ createdAt: -1 });
    res.json(records);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});





app.get('/api/init-admin', async (req, res) => {
  await initializeAdmin();
  res.send('Tried initializing admin');
});


// if (process.env.NODE_ENV !== 'production') {
//   const PORT = process.env.PORT || 3000;
//   app.listen(PORT, () => {
//     console.log(`Server running on http://localhost:${PORT}`);
//   });
// }


export default app;


