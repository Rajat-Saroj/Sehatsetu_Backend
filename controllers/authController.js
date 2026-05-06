import User from '../models/User.js';
import generateToken from '../utils/generateToken.js';
import sendEmail from '../utils/sendEmail.js';
import crypto from 'crypto';

export const registerUser = async (req, res) => {
  try {
    const { firstName, lastName, email, password, accountType } = req.body;
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: 'User already exists' });

    const user = await User.create({ firstName, lastName, email, password, accountType });

    if (user) {
      const verificationToken = crypto.randomBytes(20).toString('hex');
      user.verificationToken = crypto.createHash('sha256').update(verificationToken).digest('hex');
      user.verificationExpire = Date.now() + 24 * 60 * 60 * 1000; 
      await user.save();

      const verifyUrl = `http://localhost:5000/api/auth/verify/${verificationToken}`;
      const message = `
        <div style="font-family: Arial; padding: 20px;">
          <h1>Welcome to SehatSetu! 🌿</h1>
          <p>Click below to verify your account:</p>
          <a href="${verifyUrl}" style="background: #15803d; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Account</a>
        </div>`;

      await sendEmail({ email: user.email, subject: 'Verify Account', message });
      res.status(201).json({ message: 'Check your email to verify account!' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({ verificationToken: hashedToken, verificationExpire: { $gt: Date.now() } });

    if (!user) return res.status(400).json({ message: 'Invalid/Expired link' });

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationExpire = undefined;
    await user.save();

    res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`);
  } catch (error) {
    res.status(500).json({ message: 'Server Error' });
  }
};

export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).populate('purchasedPrograms');

    if (user && (await user.matchPassword(password))) {
      if (!user.isVerified) return res.status(401).json({ message: 'Please verify email first!' });
      res.json({ _id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email, accountType: user.accountType, purchasedPrograms: user.purchasedPrograms, token: generateToken(user._id) });
    } else {
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// ==========================================
// 👇 NEW: PASSWORD RECOVERY FUNCTIONS 👇
// ==========================================

// @desc    Forgot Password (Send the email)
// @route   POST /api/auth/forgotpassword
export const forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).json({ message: 'There is no user with that email address.' });
    }

    // 1. Generate a reset token
    const resetToken = crypto.randomBytes(20).toString('hex');

    // 2. Hash it and save it to the database, valid for only 10 minutes!
    user.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; 
    await user.save();

    // 3. Create the reset URL (This goes directly to React!)
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    // 4. Build the email
    const message = `
      <div style="font-family: Arial; padding: 20px;">
        <h1 style="color: #15803d;">Password Reset Request 🔐</h1>
        <p>You are receiving this email because you (or someone else) requested a password reset for your SehatSetu account.</p>
        <p>Please click the button below to set a new password:</p>
        <div style="margin: 30px 0;">
          <a href="${resetUrl}" style="background-color: #15803d; color: white; padding: 14px 28px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Reset Password</a>
        </div>
        <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
        <p style="color: #999;">This link will expire in 10 minutes.</p>
      </div>
    `;

    try {
      await sendEmail({
        email: user.email,
        subject: 'SehatSetu - Password Reset Request',
        message: message,
      });

      res.status(200).json({ message: 'Email sent successfully!' });
    } catch (err) {
      // If email fails, clear the token so they can try again
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();
      return res.status(500).json({ message: 'Email could not be sent' });
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// @desc    Reset Password (Save the new password)
// @route   PUT /api/auth/resetpassword/:token
export const resetPassword = async (req, res) => {
  try {
    // 1. Hash the token from the URL to match the database
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    // 2. Find the user with that token AND ensure it hasn't expired (10 min limit)
    const user = await User.findOne({
      resetPasswordToken: hashedToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired reset link. Please request a new one.' });
    }

    // 3. Set the new password (your User.js pre-save hook will automatically hash this!)
    user.password = req.body.password;

    // 4. Clean up the database tokens
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    res.status(200).json({ message: 'Password reset successful! You can now log in.' });
  } catch (error) {
    res.status(500).json({ message: 'Server Error' });
  }
};