require('dotenv').config(); // Load environment variables
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: true
}));

app.use((req, res, next) => {
    res.locals.session = req.session;  // makes session available to all EJS templates
    next();
});


// Set EJS as the template engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// Define Event Schema & Model
const eventSchema = new mongoose.Schema({
    name: String,
    date: String,
    venue:String,
    description: String,
    rules:String
});
const Event = mongoose.model('Event', eventSchema);

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

const adminSchema = new mongoose.Schema({
    name: String,
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});

const Admin = mongoose.model('Admin', adminSchema);

app.use(express.static('public'));
// Routes
app.get('/', (req, res) => {
    res.render('home');  
});

app.get('/index', async (req, res) => {
    try {
        const events = await Event.find(); 
        res.render('index', { events });  
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching events");
    }
});
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(400).send("User not found");
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).send("Invalid credentials");
        }
        req.session.isAdmin = false;
        res.redirect('/index'); // ✅ Authenticated successfully
    } catch (err) {
        console.error(err);
        res.status(500).send("Error logging in");
    }
});








app.get('/signup', (req, res) => res.render('signup'));


app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });

        await newUser.save();
        res.redirect('/login');  // Redirect to login after signup
    } catch (err) {
        console.error(err);
        res.status(500).send("Error signing up");
    }
});






// Show Event Form
app.get('/event', (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Access denied: Admins only');
    }
    res.render('event');
});
app.post('/event', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send('Access denied: Admins only');
    }

    try {
        const { name, date, venue, description,rules } = req.body;
        const newEvent = new Event({ name, date, venue, description,rules });
        await newEvent.save();
        res.redirect('/index');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error saving event");
    }
});

// Fetch and Display Events
app.get('/events', async (req, res) => {
    try {
        const events = await Event.find();
        res.render('events', { events });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching events");
    }
});

app.get('/admin-signup', (req, res) => res.render('admin-signup'));

app.post('/admin-signup', async (req, res) => {
    const { name, email, password } = req.body;

    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newAdmin = new Admin({ name, email, password: hashedPassword });

    try {
        await newAdmin.save();
        res.redirect('/admin-login');  // Redirect to login after signup
    } catch (err) {
        console.error(err);
        res.status(500).send("Error signing up admin");
    }
});



app.get('/admin-login', (req, res) => res.render('admin-login'));
app.post('/admin-login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const admin = await Admin.findOne({ email });

        if (!admin) {
            return res.status(400).send('Admin not found');
        }

        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
            return res.status(400).send('Invalid credentials');
        }

        req.session.isAdmin = true;  // ✅ Set admin session
        res.redirect('/index');
    } catch (err) {
        console.error(err);
        res.status(500).send('Error logging in');
    }
});


app.get('/search', async (req, res) => {
    const query = req.query.query;

    try {
        let events;

        if (!query || query.trim() === "") {
            events = await Event.find(); // show all events
        } else {
            events = await Event.find({
                $or: [
                    { name: { $regex: query, $options: 'i' } },
                    { venue: { $regex: query, $options: 'i' } },
                    { description: { $regex: query, $options: 'i' } }
                ]
            });
        }

        res.render('index', { events });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error processing search");
    }
});

app.post('/delete-event/:id', async (req, res) => {
    if (!req.session.isAdmin) {
        return res.status(403).send("Access denied");
    }

    try {
        await Event.findByIdAndDelete(req.params.id);
        res.redirect('/index');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error deleting event");
    }
});
app.get('/events/:id', async (req, res) => {
    try {
        const event = await Event.findById(req.params.id);
        if (!event) {
            return res.status(404).send("Event not found");
        }
        res.render('details', { event });
    } catch (err) {
        console.error(err);
        res.status(500).send("Error fetching event details");
    }
});


const PORT = process.env.PORT || 2000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
