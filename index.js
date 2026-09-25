require('dotenv').config();
const express = require('express');
const cors = require('cors');
const compression = require('compression');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.disable('x-powered-by');

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/chronicle_mag';
const DB_NAME = process.env.DB_NAME || 'chronicle_mag';
const JWT_SECRET = process.env.JWT_SECRET || 'chronicle_editorial_secret_jwt_key_2026';

// Strict CORS Origin Allowlist (No Wildcard *)
const ALLOWED_ORIGINS = new Set([
  'https://chronicle-magazine.vercel.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  ...(process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN.split(',').map((o) => o.trim()).filter(Boolean)
    : []),
  ...(process.env.NEXT_PUBLIC_SITE_URL ? [process.env.NEXT_PUBLIC_SITE_URL.trim()] : []),
]);

// Helper to validate external HTTPS URLs and prevent SSRF against internal/private networks
function isSafeExternalHttpsUrl(urlStr) {
  if (!urlStr || typeof urlStr !== 'string') return false;
  try {
    const parsed = new URL(urlStr.trim());
    if (parsed.protocol !== 'https:') return false;
    const host = parsed.hostname.toLowerCase();
    // Block loopback, link-local metadata (169.254.169.254), and private RFC1918 ranges
    if (
      host === 'localhost' ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host === '[::1]' ||
      /^127\./.test(host) ||
      /^10\./.test(host) ||
      /^192\.168\./.test(host) ||
      /^169\.254\./.test(host) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host) ||
      /^0\./.test(host)
    ) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

const SSRF_PAYLOAD_REGEX = /169\.254\.169\.254|metadata\.google\.internal|file:\/\/|gopher:\/\/|dict:\/\//i;

// Middleware
app.use(compression());

// Security Headers & Strict Cross-Origin Enforcement
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('Vary', 'Origin');

  const origin = req.headers.origin;
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({
      success: false,
      error: 'Forbidden: Origin not permitted by CORS policy.'
    });
  }

  // Inspect raw URL / query string for cloud metadata SSRF probes
  if (SSRF_PAYLOAD_REGEX.test(decodeURIComponent(req.originalUrl || ''))) {
    return res.status(400).json({
      success: false,
      error: 'Bad Request: Disallowed internal network target.'
    });
  }

  next();
});

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || ALLOWED_ORIGINS.has(origin)) {
        return callback(null, origin || 'https://chronicle-magazine.vercel.app'|| 'http://localhost:3000');
      }
      return callback(null, false);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
  })
);

app.use(express.json({ limit: '250kb' }));

// Inspect JSON request bodies for SSRF metadata probes
app.use((req, res, next) => {
  if (req.body && typeof req.body === 'object') {
    const serialized = JSON.stringify(req.body);
    if (SSRF_PAYLOAD_REGEX.test(serialized)) {
      return res.status(400).json({
        success: false,
        error: 'Bad Request: Disallowed internal network address in payload.'
      });
    }
  }
  next();
});

// MongoDB Client & Collections references
let client;
let db;
let storiesCollection;
let commentsCollection;
let adminsCollection;
let usersCollection;
let categoriesCollection;

// Helper to convert id string to MongoDB query (ObjectId or slug)
function buildStoryQuery(idOrSlug) {
  const safeId = String(idOrSlug || '').trim();
  if (ObjectId.isValid(safeId) && String(new ObjectId(safeId)) === safeId) {
    return { $or: [{ _id: new ObjectId(safeId) }, { slug: safeId }] };
  }
  return { slug: safeId };
}

// User Authentication Middleware
function verifyUserToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. Please log in to your reader account.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Session expired or invalid token.' });
  }
}

// Admin Authentication Middleware
async function verifyAdminToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Access denied. No admin token provided.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin' && decoded.role !== 'superadmin') {
      return res.status(403).json({ error: 'Administrative privileges required.', revoked: true });
    }

    // Dynamic Database Verification: Verify admin account has not been revoked
    if (adminsCollection && usersCollection) {
      let isStillAdmin = false;

      // 1. Check adminsCollection by username
      if (decoded.username) {
        const adminDoc = await adminsCollection.findOne({ username: decoded.username });
        if (adminDoc) {
          isStillAdmin = true;
          decoded.role = adminDoc.role || decoded.role;
        }
      }

      // 2. Check usersCollection by email or id
      if (!isStillAdmin) {
        const queryList = [];
        if (decoded.email) queryList.push({ email: decoded.email.trim().toLowerCase() });
        if (decoded.username && decoded.username.includes('@')) queryList.push({ email: decoded.username.trim().toLowerCase() });
        if (decoded.id && ObjectId.isValid(decoded.id)) queryList.push({ _id: new ObjectId(decoded.id) });

        if (queryList.length > 0) {
          const userDoc = await usersCollection.findOne({ $or: queryList });
          if (userDoc) {
            if (userDoc.role === 'admin' || userDoc.role === 'superadmin') {
              isStillAdmin = true;
              decoded.role = userDoc.role;
            } else {
              // Explicitly revoked / demoted to reader
              return res.status(403).json({
                error: 'Administrator privileges have been revoked by super admin.',
                revoked: true
              });
            }
          }
        }
      }

      if (!isStillAdmin) {
        return res.status(403).json({
          error: 'Administrator account not found or privileges have been revoked.',
          revoked: true
        });
      }
    }

    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired admin token.', revoked: true });
  }
}

// -------------------------------------------------------------
// Sample Initial Data (Seeding)
// -------------------------------------------------------------
const sampleCategories = [
  {
    name: 'Tech Leaders',
    slug: 'tech-leaders',
    description: 'Innovators and founders reshaping global computing, digital frontiers, and artificial intelligence.'
  },
  {
    name: 'World Leaders',
    slug: 'world-leaders',
    description: 'Statesmen, peacemakers, and historic figures who guided nations through revolution and peace.'
  },
  {
    name: 'Pioneers',
    slug: 'pioneers',
    description: 'Courageous explorers, barrier-breakers, and scientific trailblazers who expanded human horizons.'
  },
  {
    name: 'Athletes & Sports',
    slug: 'athletes-sports',
    description: 'Champions of human endurance, teamwork, resilience, and extraordinary athletic mastery.'
  },
  {
    name: 'Innovators',
    slug: 'innovators',
    description: 'Inventors, polymaths, and visionaries transforming industry and human possibility.'
  },
  {
    name: 'Arts & Culture',
    slug: 'arts-culture',
    description: 'Literary masters, visual artists, and architects of modern culture and creative expression.'
  }
];

const sampleStories = [
  {
    title: 'Steve Jobs: The Visionary Who Revolutionized Everyday Technology',
    slug: 'steve-jobs',
    category: 'Tech Leaders',
    coverImage: 'https://images.unsplash.com/photo-1519389950473-47ba0277781c?auto=format&fit=crop&w=1200&q=80',
    summary: 'From an ordinary garage in Los Altos to leading the world\'s most valuable design-driven company, Steve Jobs reshaped personal computing, animated cinema, music, phones, and tablet computing.',
    author: 'Editorial Desk',
    readingTime: '6 min read',
    featured: true,
    views: 1420,
    likes: 384,
    milestones: [
      { year: '1955', event: 'Born in San Francisco, California; adopted by Paul and Clara Jobs.' },
      { year: '1976', event: 'Co-founded Apple Computer Company with Steve Wozniak in his family garage.' },
      { year: '1984', event: 'Unveiled the original Macintosh computer with an iconic Super Bowl commercial.' },
      { year: '1986', event: 'Acquired the Computer Graphics Division from Lucasfilm, founding Pixar Animation Studios.' },
      { year: '1997', event: 'Returned to Apple as interim CEO, leading the "Think Different" renaissance.' },
      { year: '2001', event: 'Launched the iPod and revolutionized the entire global digital music industry.' },
      { year: '2007', event: 'Introduced the revolutionary iPhone at Macworld San Francisco.' },
      { year: '2010', event: 'Introduced the iPad, defining the modern tablet computing era.' }
    ],
    content: `Steve Jobs was not merely a technologist; he was a cultural architect who believed that the intersection of technology and the liberal arts created things that made human hearts sing.

Growing up in Silicon Valley during the birth of semiconductor electronics, Jobs observed the magic of machines early on. When he teamed up with the engineering genius Steve Wozniak in 1976, they produced the Apple I and Apple II, effectively kickstarting the personal computer revolution.

### The Wilderness Years & Pixar
After being ousted from Apple in 1985 following disputes with the board, Jobs did not retreat into obscurity. He founded NeXT Computer, which pioneered object-oriented programming frameworks that would eventually become the foundation of modern macOS and iOS. Concurrently, his investment in Pixar produced "Toy Story" (1995), the world's first entirely computer-animated feature film.

### The Triumphant Return
In late 1996, Apple was months away from bankruptcy when it bought NeXT. Jobs took the helm again, simplified Apple's bloated product matrix into a 2x2 grid, and initiated a string of era-defining products: the candy-colored iMac G3, the minimalist iPod, and the iTunes Store.

When Jobs unveiled the iPhone in January 2007, he famously described it as three devices in one: a widescreen iPod with touch controls, a revolutionary mobile phone, and a breakthrough internet communicator. It transformed global commerce, human communication, and modern society forever.

Jobs' legacy is not just Apple's hardware, but an uncompromising commitment to craft, typography, taste, and the audacity to believe that one person can put a dent in the universe.`,
    createdAt: new Date('2026-01-10T10:00:00Z'),
    updatedAt: new Date('2026-01-10T10:00:00Z')
  },
  {
    title: 'Marie Curie: The Relentless Pioneer of Radioactivity',
    slug: 'marie-curie',
    category: 'Pioneers',
    coverImage: 'https://images.unsplash.com/photo-1532094349884-543bc11b234d?auto=format&fit=crop&w=1200&q=80',
    summary: 'The first person to win two Nobel Prizes in distinct scientific fields, Marie Skłodowska Curie broke scientific and social barriers to unlock the mysteries of the atomic nucleus.',
    author: 'Science Section',
    readingTime: '7 min read',
    featured: true,
    views: 980,
    likes: 295,
    milestones: [
      { year: '1867', event: 'Born Maria Skłodowska in Warsaw, Kingdom of Poland.' },
      { year: '1891', event: 'Moved to Paris to study physics and mathematics at the prestigious Sorbonne.' },
      { year: '1898', event: 'Discovered polonium and radium alongside her husband Pierre Curie.' },
      { year: '1903', event: 'Awarded the Nobel Prize in Physics alongside Pierre Curie and Henri Becquerel.' },
      { year: '1911', event: 'Awarded her second Nobel Prize, in Chemistry, for isolating pure radium.' },
      { year: '1914', event: 'Equipped mobile radiological units ("Little Curies") to treat wounded WWI soldiers.' },
      { year: '1934', event: 'Passed away, leaving an eternal legacy in modern atomic physics and oncology.' }
    ],
    content: `Few scientists have exerted as profound and enduring an impact on the trajectory of modern physics and medicine as Marie Skłodowska Curie. 

Born in partition-era Warsaw, where higher education was forbidden to women under Russian rule, young Maria attended the underground "Flying University" while working years as a governess to fund her older sister's medical studies in France.

### The Sorbonne and Unprecedented Discoveries
Arriving in Paris in 1891, she endured poverty, cold garrets, and intellectual skepticism to top her master's examinations at the Sorbonne. Partnering with Pierre Curie in a rudimentary, drafty wooden shed at the School of Chemistry, she analyzed pitchblende ores with an electrometer, identifying radiations far beyond uranium.

She coined the term "radioactivity" and isolated two brand-new elements: polonium (named proudly after her occupied homeland) and radium.

### A Dual Laureate and Humanitarian
In 1903, Curie became the first woman to receive the Nobel Prize in Physics. When Pierre tragically died in a traffic accident in 1906, Marie assumed his professorship, becoming the first female professor at the Sorbonne. In 1911, she captured the Nobel Prize in Chemistry for her isolation of radium, remaining the only individual in history honored across two different natural sciences.

During World War I, rather than remaining in laboratories, she engineered mobile X-ray vans and trained over 150 female radiological technicians, directly saving tens of thousands of battlefield casualties. Her life remains the ultimate testament to scientific devotion over personal hardship.`,
    createdAt: new Date('2026-01-15T12:00:00Z'),
    updatedAt: new Date('2026-01-15T12:00:00Z')
  },
  {
    title: 'Nelson Mandela: The Long Walk to Freedom & Reconciliation',
    slug: 'nelson-mandela',
    category: 'World Leaders',
    coverImage: 'https://images.unsplash.com/photo-1541872703-74c5e44368f9?auto=format&fit=crop&w=1200&q=80',
    summary: 'Imprisoned for 27 years on Robben Island, Nelson Mandela emerged with neither vengeance nor bitterness, orchestrating South Africa\'s peaceful transition from apartheid to multiracial democracy.',
    author: 'World Affairs Desk',
    readingTime: '8 min read',
    featured: false,
    views: 1120,
    likes: 310,
    milestones: [
      { year: '1918', event: 'Born Rolihlahla Mandela in Mvezo, South Africa.' },
      { year: '1944', event: 'Helped establish the African National Congress (ANC) Youth League.' },
      { year: '1964', event: 'Sentenced to life imprisonment at the conclusion of the Rivonia Trial.' },
      { year: '1990', event: 'Released unconditionally from Victor Verster Prison after 27 years.' },
      { year: '1993', event: 'Awarded the Nobel Peace Prize alongside President F.W. de Klerk.' },
      { year: '1994', event: 'Inaugurated as the first Black President of democratic South Africa.' },
      { year: '1995', event: 'United the nation behind the Springboks rugby team in the Rugby World Cup.' }
    ],
    content: `Nelson Mandela stands among history's rarest leaders: a revolutionary who dismantled institutional racism not with retaliatory violence, but through the transformative discipline of moral authority and reconciliation.

Following decades of nonviolent anti-apartheid campaigns met with brutal state repression, Mandela formed the armed wing Umkhonto we Sizwe. Captured in 1962, he stood in the dock at the 1964 Rivonia Trial and uttered the words that echoed worldwide: "I have cherished the ideal of a democratic and free society... It is an ideal for which I am prepared to die."

### The Crucible of Robben Island
Mandela endured harsh manual labor at the limestone quarries of Robben Island. Rather than succumb to despair, he converted prison into an academy, studying Afrikaans to understand the mindset and language of his jailers, earning their respect through unwavering dignity.

### The Miracle of 1994
Upon his release in 1990 by President F.W. de Klerk, many feared a racial civil war. Mandela guided the negotiations with unmatched statecraft. In 1994, millions of South Africans queued for hours to cast their first democratic ballots, electing Mandela president of the new "Rainbow Nation."

He formed the Truth and Reconciliation Commission, chaired by Archbishop Desmond Tutu, demonstrating to the globe that justice and forgiveness could walk hand in hand.`,
    createdAt: new Date('2026-01-20T14:30:00Z'),
    updatedAt: new Date('2026-01-20T14:30:00Z')
  },
  {
    title: 'Muhammad Ali: The Greatest in the Ring and Beyond',
    slug: 'muhammad-ali',
    category: 'Athletes & Sports',
    coverImage: 'https://images.unsplash.com/photo-1549719386-74dfcbf7dbed?auto=format&fit=crop&w=1200&q=80',
    summary: 'He floated like a butterfly and stung like a bee, but Muhammad Ali\'s greatest battles were fought outside the ropes for civil rights, religious freedom, and human conscience.',
    author: 'Sports Culture Desk',
    readingTime: '5 min read',
    featured: false,
    views: 840,
    likes: 245,
    milestones: [
      { year: '1942', event: 'Born Cassius Marcellus Clay Jr. in Louisville, Kentucky.' },
      { year: '1960', event: 'Won the Light Heavyweight Olympic Gold Medal in Rome.' },
      { year: '1964', event: 'Defeated Sonny Liston to claim the World Heavyweight Championship; adopted the name Muhammad Ali.' },
      { year: '1967', event: 'Refused induction into the U.S. Army on religious grounds, sacrificing his prime boxing years.' },
      { year: '1971', event: 'U.S. Supreme Court unanimously overturned his draft conviction.' },
      { year: '1974', event: 'Defeated George Foreman in the "Rumble in the Jungle" in Zaire.' },
      { year: '1996', event: 'Lit the Olympic flame in Atlanta with dignity, celebrated globally.' }
    ],
    content: `Muhammad Ali redefined what it meant to be a professional athlete. He possessed unmatched hand speed, poetic ring movement, and a verbal dexterity that laid the groundwork for modern sports entertainment and hip-hop lyrical rhythm.

Yet his true greatness was forged when he was stripped of his titles and exiled from boxing at the zenith of his athletic prime in 1967. Objecting to the Vietnam War, he stated simply: "I ain't got no quarrel with them Vietcong... No Vietcong ever called me nigger."

He toured college campuses for three and a half years, speaking out on racial injustice, anti-imperialism, and religious identity. When he returned to the ring, his lightning reflexes had slowed, but his psychological resolve was impenetrable.

His dramatic victories over Joe Frazier in the "Thrilla in Manila" and George Foreman in the "Rumble in the Jungle" cemented his standing as an immortal champion of both sports and conscience.`,
    createdAt: new Date('2026-02-01T09:15:00Z'),
    updatedAt: new Date('2026-02-01T09:15:00Z')
  },
  {
    title: 'Ada Lovelace: The Enchantress of Numbers and Mother of Code',
    slug: 'ada-lovelace',
    category: 'Pioneers',
    coverImage: 'https://images.unsplash.com/photo-1509228468518-180dd4864904?auto=format&fit=crop&w=1200&q=80',
    summary: 'A century before the first electronic computer whirred to life, Augusta Ada King, Countess of Lovelace foresaw that machines could manipulate symbols, music, and poetry.',
    author: 'Tech History',
    readingTime: '6 min read',
    featured: false,
    views: 730,
    likes: 180,
    milestones: [
      { year: '1815', event: 'Born in London, the daughter of poet Lord Byron and mathematician Annabella Milbanke.' },
      { year: '1833', event: 'Met polymath Charles Babbage and was mesmerized by his Difference Engine prototype.' },
      { year: '1843', event: 'Published translated notes on Babbage\'s Analytical Engine, containing Note G (the first computer algorithm).' },
      { year: '1980', event: 'The U.S. Department of Defense named high-integrity programming language Ada in her honor.' }
    ],
    content: `In the 1840s, while the Industrial Revolution was clanking with steam and iron, Ada Lovelace looked into Charles Babbage's conceptual blueprints for the Analytical Engine and saw the future of the digital universe.

While Babbage focused primarily on arithmetic calculation, Lovelace realized that if information of any kind—including music, images, and language—could be translated into numerical representations, the machine could compose elaborate musical pieces, render graphics, and solve scientific inquiries of unlimited complexity.

In her famous Note G, she described an algorithm for calculating Bernoulli numbers using the Analytical Engine. Historians universally recognize this as the first computer algorithm ever written, making Lovelace the world's first computer programmer.`,
    createdAt: new Date('2026-02-12T16:00:00Z'),
    updatedAt: new Date('2026-02-12T16:00:00Z')
  },
  {
    title: 'Leonardo da Vinci: The Boundless Mind of the Renaissance',
    slug: 'leonardo-da-vinci',
    category: 'Pioneers',
    coverImage: 'https://images.unsplash.com/photo-1579783902614-a3fb3927b675?auto=format&fit=crop&w=1200&q=80',
    summary: 'Painter of the Mona Lisa and The Last Supper, Leonardo was also an engineer, anatomist, and visionary inventor whose notebooks foresaw flight, hydraulics, and robotics.',
    author: 'Arts & Culture',
    readingTime: '7 min read',
    featured: false,
    views: 890,
    likes: 215,
    milestones: [
      { year: '1452', event: 'Born out of wedlock in the Tuscan hill town of Vinci.' },
      { year: '1466', event: 'Apprenticed in Florence to the master artist and sculptor Andrea del Verrocchio.' },
      { year: '1482', event: 'Moved to Milan to serve Duke Ludovico Sforza as military engineer, painter, and court visionary.' },
      { year: '1498', event: 'Completed The Last Supper in the refectory of Santa Maria delle Grazie.' },
      { year: '1503', event: 'Began painting the portrait of Lisa Gherardini, the Mona Lisa.' },
      { year: '1519', event: 'Died in Amboise, France, in the arms of King Francis I according to legend.' }
    ],
    content: `Leonardo da Vinci personifies the universal genius of the Italian Renaissance. His relentless curiosity pushed the boundaries of painting, anatomy, botany, cartography, and hydrodynamic engineering.

Leonardo believed that sight was the highest sense and that true knowledge derived from firsthand empirical observation rather than dogmatic scholasticism. In secret nocturnal dissections, he mapped the coronary arteries, the optical nerves, and the muscular mechanics of the human smile with breathtaking anatomical fidelity.

His codices—thousands of mirror-written pages filled with sketches of helicopters, parachutes, automated looms, and perpetual motion machines—remain one of the most awe-inspiring records of human imagination in world history.`,
    createdAt: new Date('2026-02-20T11:00:00Z'),
    updatedAt: new Date('https://chronicle-magazine.vercel.app',
  'http://localhost:3000',
  'http://127.0.0.1:3000','2026-02-20T11:00:00Z')
  }
];

// -------------------------------------------------------------
// Database Connection & Initialization
// -------------------------------------------------------------
async function initializeDatabase() {
  try {
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log('Successfully connected to MongoDB native driver!');

    db = client.db(DB_NAME);
    storiesCollection = db.collection('stories');
    commentsCollection = db.collection('comments');
    adminsCollection = db.collection('admins');
    usersCollection = db.collection('users');
    categoriesCollection = db.collection('categories');

    // Setup Indexes
    await storiesCollection.createIndex({ slug: 1 }, { unique: true });
    await storiesCollection.createIndex({ category: 1 });
    await storiesCollection.createIndex({ views: -1 });
    await storiesCollection.createIndex({ createdAt: -1 });
    await commentsCollection.createIndex({ storyId: 1 });
    await commentsCollection.createIndex({ createdAt: -1 });
    await adminsCollection.createIndex({ username: 1 }, { unique: true });
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await categoriesCollection.createIndex({ name: 1 }, { unique: true });
    await categoriesCollection.createIndex({ slug: 1 }, { unique: true });

    // Auto-seed categories if empty
    const categoriesCount = await categoriesCollection.countDocuments();
    if (categoriesCount === 0) {
      console.log('Seeding initial categories into MongoDB...');
      await categoriesCollection.insertMany(
        sampleCategories.map(c => ({
          ...c,
          createdAt: new Date()
        }))
      );
      console.log(`Seeded ${sampleCategories.length} categories.`);
    }

    // Auto-seed stories if empty
    const storiesCount = await storiesCollection.countDocuments();
    if (storiesCount === 0) {
      console.log('Seeding initial biographies into MongoDB...');
      await storiesCollection.insertMany(sampleStories);
      console.log(`Seeded ${sampleStories.length} stories.`);

      // Seed initial comments for Steve Jobs
      const steve = await storiesCollection.findOne({ slug: 'steve-jobs' });
      if (steve) {
        await commentsCollection.insertMany([
          {
            storyId: steve._id.toString(),
            name: 'Sarah Jenkins',
            comment: 'Steve Jobs changed how my entire generation interacts with typography and digital devices. Brilliant profile!',
            createdAt: new Date('2026-02-15T08:30:00Z')
          },
          {
            storyId: steve._id.toString(),
            name: 'Marcus Chen',
            comment: 'The quote about the intersection of technology and liberal arts still inspires my product design work every single day.',
            createdAt: new Date('2026-02-18T14:20:00Z')
          }
        ]);
      }
    }

    // Seed admin ONLY if explicitly defined in environment variables (no hardcoded credentials)
    const adminCount = await adminsCollection.countDocuments();
    if (adminCount === 0 && process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
      const salt = await bcrypt.genSalt(10);
      const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, salt);

      await adminsCollection.insertOne({
        username: process.env.ADMIN_USERNAME.trim(),
        passwordHash,
        role: 'superadmin',
        createdAt: new Date()
      });
      console.log(`Initialized administrator account from environment: "${process.env.ADMIN_USERNAME.trim()}"`);
    }

  } catch (err) {
    console.error('Failed to connect to MongoDB:', err.message);
  }
}

// -------------------------------------------------------------
// Public Routes: Stories & Reader Interactions
// -------------------------------------------------------------

// GET /api/stories: Browse stories with filters (category, top-viewed, featured, search)
app.get('/api/stories', async (req, res) => {
  try {
    const { category, featured, sort, search, limit = 50 } = req.query;
    const filter = {};

    if (category && category !== 'All') {
      filter.category = category;
    }

    if (featured === 'true') {
      filter.featured = true;
    }

    if (search) {
      filter.$or = [
        { title: { $regex: search, $options: 'i' } },
        { summary: { $regex: search, $options: 'i' } },
        { content: { $regex: search, $options: 'i' } }
      ];
    }

    let sortOption = { createdAt: -1 };
    if (sort === 'views' || sort === 'top' || sort === 'trending') {
      sortOption = { views: -1 };
    } else if (sort === 'likes') {
      sortOption = { likes: -1 };
    }

    const stories = await storiesCollection
      .find(filter, {
        projection: {
          title: 1,
          slug: 1,
          category: 1,
          coverImage: 1,
          summary: 1,
          author: 1,
          readingTime: 1,
          featured: 1,
          views: 1,
          likes: 1,
          createdAt: 1,
          updatedAt: 1
        }
      })
      .sort(sortOption)
      .limit(parseInt(limit, 10))
      .toArray();

    // Browser caching: 30s fresh, 120s stale-while-revalidate for instant back/forward navigation
    res.set('Cache-Control', 'public, max-age=30, stale-while-revalidate=120');

    res.json({
      success: true,
      count: stories.length,
      data: stories
    });
  } catch (err) {
    console.error('Error fetching stories:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch stories.' });
  }
});

// -------------------------------------------------------------
// Category Management APIs (Dynamic)
// -------------------------------------------------------------

// GET /api/categories: Dynamic categories list with active story count
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await categoriesCollection.find({}).sort({ name: 1 }).toArray();

    // Compute count for each category from stories collection
    const storyCounts = await storiesCollection.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]).toArray();

    const countMap = {};
    storyCounts.forEach(c => {
      if (c._id) {
        countMap[c._id.toLowerCase()] = c.count;
      }
    });

    const enriched = categories.map(cat => ({
      _id: cat._id,
      name: cat.name,
      slug: cat.slug,
      description: cat.description || '',
      count: countMap[cat.name.toLowerCase()] || 0,
      createdAt: cat.createdAt
    }));

    // Cache categories for 120s fresh, 600s stale-while-revalidate
    res.set('Cache-Control', 'public, max-age=120, stale-while-revalidate=600');

    res.json({
      success: true,
      count: enriched.length,
      data: enriched
    });
  } catch (err) {
    console.error('Error fetching categories:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch categories.' });
  }
});

// POST /api/categories: Create a new category (Admin only)
app.post('/api/categories', verifyAdminToken, async (req, res) => {
  try {
    const { name, description } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: 'Category name is required.' });
    }

    const trimmedName = name.trim();
    const cleanSlug = trimmedName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)+/g, '');

    if (!cleanSlug) {
      return res.status(400).json({ success: false, error: 'Category name must contain alphanumeric characters.' });
    }

    // Check duplicate name or slug (case-insensitive)
    const existing = await categoriesCollection.findOne({
      $or: [
        { name: { $regex: new RegExp(`^${trimmedName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } },
        { slug: cleanSlug }
      ]
    });

    if (existing) {
      return res.status(409).json({ success: false, error: `Category "${trimmedName}" already exists.` });
    }

    const newCategory = {
      name: trimmedName,
      slug: cleanSlug,
      description: description ? description.trim() : '',
      createdAt: new Date(),
      createdBy: req.admin.username || req.admin.email || 'admin'
    };

    const result = await categoriesCollection.insertOne(newCategory);
    res.status(201).json({
      success: true,
      data: { ...newCategory, _id: result.insertedId, count: 0 },
      message: `Category "${trimmedName}" created successfully.`
    });
  } catch (err) {
    console.error('Error creating category:', err);
    res.status(500).json({ success: false, error: 'Failed to create category.' });
  }
});

// PUT /api/categories/:id: Update category details (Admin only)
app.put('/api/categories/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid category ID.' });
    }

    const category = await categoriesCollection.findOne({ _id: new ObjectId(id) });
    if (!category) {
      return res.status(404).json({ success: false, error: 'Category not found.' });
    }

    const { name, description } = req.body;
    const updateFields = { updatedAt: new Date() };
    const oldName = category.name;

    if (name && name.trim() && name.trim() !== category.name) {
      const trimmedName = name.trim();
      const cleanSlug = trimmedName
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)+/g, '');

      // Check if duplicate exists with another ID
      const duplicate = await categoriesCollection.findOne({
        _id: { $ne: new ObjectId(id) },
        $or: [
          { name: { $regex: new RegExp(`^${trimmedName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } },
          { slug: cleanSlug }
        ]
      });

      if (duplicate) {
        return res.status(409).json({ success: false, error: `Category "${trimmedName}" already exists.` });
      }

      updateFields.name = trimmedName;
      updateFields.slug = cleanSlug;

      // Propagate category name update across existing stories
      await storiesCollection.updateMany(
        { category: oldName },
        { $set: { category: trimmedName } }
      );
    }

    if (description !== undefined) {
      updateFields.description = description.trim();
    }

    await categoriesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: updateFields }
    );

    const updated = await categoriesCollection.findOne({ _id: new ObjectId(id) });
    res.json({
      success: true,
      data: updated,
      message: 'Category updated successfully.'
    });
  } catch (err) {
    console.error('Error updating category:', err);
    res.status(500).json({ success: false, error: 'Failed to update category.' });
  }
});

// DELETE /api/categories/:id: Delete category (Admin only)
app.delete('/api/categories/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid category ID.' });
    }

    const category = await categoriesCollection.findOne({ _id: new ObjectId(id) });
    if (!category) {
      return res.status(404).json({ success: false, error: 'Category not found.' });
    }

    const storyCount = await storiesCollection.countDocuments({ category: category.name });
    await categoriesCollection.deleteOne({ _id: new ObjectId(id) });

    res.json({
      success: true,
      message: `Category "${category.name}" removed successfully.${storyCount > 0 ? ` (${storyCount} stories currently reference this category)` : ''}`
    });
  } catch (err) {
    console.error('Error deleting category:', err);
    res.status(500).json({ success: false, error: 'Failed to delete category.' });
  }
});

// GET /api/stories/:id: Retrieve story details & atomically increment views
app.get('/api/stories/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const query = buildStoryQuery(id);

    // Atomically increment views and return the updated document
    const updatedStory = await storiesCollection.findOneAndUpdate(
      query,
      { $inc: { views: 1 } },
      { returnDocument: 'after' }
    );

    if (!updatedStory) {
      return res.status(404).json({ success: false, error: 'Biography not found.' });
    }

    res.json({
      success: true,
      data: updatedStory
    });
  } catch (err) {
    console.error('Error fetching story:', err);
    res.status(500).json({ success: false, error: 'Failed to load biography.' });
  }
});

// POST /api/stories/:id/like: Atomically toggle like for authenticated reader
app.post('/api/stories/:id/like', verifyUserToken, async (req, res) => {
  try {
    const { id } = req.params;
    const query = buildStoryQuery(id);
    const userId = req.user.id || req.user.email || req.user.username;

    const story = await storiesCollection.findOne(query);
    if (!story) {
      return res.status(404).json({ success: false, error: 'Biography profile not found.' });
    }

    const storyId = story._id.toString();
    const storySlug = story.slug;

    // Retrieve user document to inspect liked stories
    let user = null;
    if (ObjectId.isValid(req.user.id)) {
      user = await usersCollection.findOne({ _id: new ObjectId(req.user.id) });
    }
    if (!user && (req.user.email || req.user.username)) {
      user = await usersCollection.findOne({
        $or: [
          { email: (req.user.email || req.user.username).toLowerCase() },
          { username: req.user.username }
        ]
      });
    }

    const likedStories = user?.likedStories || [];
    const storyLikedBy = story.likedBy || [];
    const hasAlreadyLiked =
      likedStories.includes(storyId) ||
      (storySlug && likedStories.includes(storySlug)) ||
      storyLikedBy.includes(userId);

    let updatedLikes = story.likes || 0;
    let isLikedNow = false;

    if (hasAlreadyLiked) {
      // Toggle OFF: unlike
      updatedLikes = Math.max(0, updatedLikes - 1);
      isLikedNow = false;

      await storiesCollection.updateOne(
        { _id: story._id },
        {
          $set: { likes: updatedLikes },
          $pull: { likedBy: userId }
        }
      );

      if (user) {
        await usersCollection.updateOne(
          { _id: user._id },
          { $pull: { likedStories: { $in: [storyId, storySlug] } } }
        );
      }
    } else {
      // Toggle ON: like
      updatedLikes = updatedLikes + 1;
      isLikedNow = true;

      await storiesCollection.updateOne(
        { _id: story._id },
        {
          $set: { likes: updatedLikes },
          $addToSet: { likedBy: userId }
        }
      );

      if (user) {
        await usersCollection.updateOne(
          { _id: user._id },
          { $addToSet: { likedStories: storyId } }
        );
      }
    }

    res.json({
      success: true,
      liked: isLikedNow,
      likes: updatedLikes,
      message: isLikedNow ? 'Appreciation recorded!' : 'Like removed.'
    });
  } catch (err) {
    console.error('Error toggling story like:', err);
    res.status(500).json({ success: false, error: 'Failed to record like.' });
  }
});

// GET /api/stories/:id/comments: Fetch all comments for a story
app.get('/api/stories/:id/comments', async (req, res) => {
  try {
    const { id } = req.params;

    // Find the story to get its ObjectId string
    const query = buildStoryQuery(id);
    const story = await storiesCollection.findOne(query);
    if (!story) {
      return res.status(404).json({ success: false, error: 'Story not found.' });
    }

    const storyIdStr = story._id.toString();
    const comments = await commentsCollection
      .find({ storyId: storyIdStr })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      count: comments.length,
      data: comments
    });
  } catch (err) {
    console.error('Error fetching comments:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch comments.' });
  }
});

// POST /api/stories/:id/comments: Add a new comment
app.post('/api/stories/:id/comments', async (req, res) => {
  try {
    const { id } = req.params;
    const { name, comment } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: 'Name is required.' });
    }
    if (!comment || !comment.trim()) {
      return res.status(400).json({ success: false, error: 'Comment message is required.' });
    }

    const query = buildStoryQuery(id);
    const story = await storiesCollection.findOne(query);
    if (!story) {
      return res.status(404).json({ success: false, error: 'Story not found.' });
    }

    const newComment = {
      storyId: story._id.toString(),
      storyTitle: story.title,
      name: name.trim(),
      comment: comment.trim(),
      userId: req.body.userId || null,
      createdAt: new Date()
    };

    const result = await commentsCollection.insertOne(newComment);
    newComment._id = result.insertedId;

    res.status(201).json({
      success: true,
      message: 'Comment posted successfully.',
      data: newComment
    });
  } catch (err) {
    console.error('Error posting comment:', err);
    res.status(500).json({ success: false, error: 'Failed to post comment.' });
  }
});

// -------------------------------------------------------------
// Reader / User Authentication Routes
// -------------------------------------------------------------

// POST /api/auth/register: Create a new reader account
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, error: 'Full name is required.' });
    }
    if (!email || !email.trim() || !email.includes('@')) {
      return res.status(400).json({ success: false, error: 'Valid email address is required.' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    const existing = await usersCollection.findOne({ email: cleanEmail });
    if (existing) {
      return res.status(400).json({ success: false, error: 'An account with this email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = {
      name: name.trim(),
      email: cleanEmail,
      passwordHash,
      role: 'reader',
      bookmarks: [],
      likedStories: [],
      createdAt: new Date()
    };

    const result = await usersCollection.insertOne(newUser);
    newUser._id = result.insertedId;

    const token = jwt.sign(
      { id: newUser._id.toString(), name: newUser.name, email: newUser.email, role: 'reader' },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      token,
      user: {
        id: newUser._id.toString(),
        name: newUser.name,
        email: newUser.email,
        role: 'reader',
        bookmarks: [],
        likedStories: []
      }
    });
  } catch (err) {
    console.error('User register error:', err);
    res.status(500).json({ success: false, error: 'Failed to register reader account.' });
  }
});

// POST /api/auth/login: Login reader account (with admin fallback)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, error: 'Email and password are required.' });
    }

    const cleanEmail = email.trim().toLowerCase();
    let user = await usersCollection.findOne({ email: cleanEmail });

    // Check if logging in with admin credentials via the unified login
    if (!user) {
      const admin = await adminsCollection.findOne({ username: email.trim() });
      if (admin) {
        const isMatch = await bcrypt.compare(password, admin.passwordHash);
        if (isMatch) {
          const token = jwt.sign(
            { id: admin._id.toString(), username: admin.username, name: admin.username, role: 'admin' },
            JWT_SECRET,
            { expiresIn: '7d' }
          );
          return res.json({
            success: true,
            message: 'Signed in as Administrator.',
            token,
            user: {
              id: admin._id.toString(),
              name: admin.username,
              username: admin.username,
              email: `${admin.username}@chronicle.mag`,
              role: 'admin',
              bookmarks: []
            }
          });
        }
      }
      return res.status(401).json({ success: false, error: 'Invalid email or password.' });
    }

    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid email or password.' });
    }

    const token = jwt.sign(
      { id: user._id.toString(), name: user.name, email: user.email, role: user.role || 'reader' },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      success: true,
      message: 'Signed in successfully.',
      token,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role || 'reader',
        bookmarks: user.bookmarks || [],
        likedStories: user.likedStories || []
      }
    });
  } catch (err) {
    console.error('User login error:', err);
    res.status(500).json({ success: false, error: 'Login service error.' });
  }
});

// GET /api/auth/me: Retrieve current logged-in reader profile
app.get('/api/auth/me', verifyUserToken, async (req, res) => {
  try {
    if (req.user.role === 'admin') {
      return res.json({
        success: true,
        user: {
          id: req.user.id,
          name: req.user.name || req.user.username,
          username: req.user.username,
          role: 'admin',
          bookmarks: [],
          likedStories: []
        }
      });
    }

    const user = await usersCollection.findOne({ _id: new ObjectId(req.user.id) });
    if (!user) {
      return res.status(404).json({ success: false, error: 'User account not found.' });
    }

    res.json({
      success: true,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: user.role || 'reader',
        bookmarks: user.bookmarks || [],
        likedStories: user.likedStories || [],
        createdAt: user.createdAt
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve user profile.' });
  }
});

// POST /api/users/bookmarks/:storyId: Toggle story bookmark
app.post('/api/users/bookmarks/:storyId', verifyUserToken, async (req, res) => {
  try {
    const { storyId } = req.params;
    const userId = req.user.id;

    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ success: false, error: 'Invalid user reference.' });
    }

    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    const bookmarks = user.bookmarks || [];
    const isBookmarked = bookmarks.includes(storyId);

    let updatedBookmarks;
    if (isBookmarked) {
      await usersCollection.updateOne(
        { _id: new ObjectId(userId) },
        { $pull: { bookmarks: storyId } }
      );
      updatedBookmarks = bookmarks.filter(id => id !== storyId);
    } else {
      await usersCollection.updateOne(
        { _id: new ObjectId(userId) },
        { $addToSet: { bookmarks: storyId } }
      );
      updatedBookmarks = [...bookmarks, storyId];
    }

    res.json({
      success: true,
      bookmarked: !isBookmarked,
      bookmarks: updatedBookmarks,
      message: !isBookmarked ? 'Story saved to your reading list.' : 'Story removed from bookmarks.'
    });
  } catch (err) {
    console.error('Bookmark error:', err);
    res.status(500).json({ success: false, error: 'Failed to update bookmark.' });
  }
});

// GET /api/users/bookmarks: Get all bookmarked stories for current user
app.get('/api/users/bookmarks', verifyUserToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    const bookmarkIds = user.bookmarks || [];
    if (bookmarkIds.length === 0) {
      return res.json({ success: true, count: 0, data: [] });
    }

    const objectIds = bookmarkIds.filter(id => ObjectId.isValid(id)).map(id => new ObjectId(id));
    const stories = await storiesCollection.find({
      $or: [
        { _id: { $in: objectIds } },
        { slug: { $in: bookmarkIds } }
      ]
    }).toArray();

    res.json({
      success: true,
      count: stories.length,
      data: stories
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve bookmarked stories.' });
  }
});

// -------------------------------------------------------------
// Admin Authentication Routes
// -------------------------------------------------------------

// POST /api/admin/login: Authenticate and issue JWT
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password are required.' });
    }

    const admin = await adminsCollection.findOne({ username: username.trim() });
    if (!admin) {
      return res.status(401).json({ success: false, error: 'Invalid username or password.' });
    }

    const isMatch = await bcrypt.compare(password, admin.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid username or password.' });
    }

    const token = jwt.sign(
      { id: admin._id.toString(), username: admin.username, role: admin.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Authentication successful.',
      token,
      admin: {
        id: admin._id.toString(),
        username: admin.username,
        role: admin.role
      }
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ success: false, error: 'Login service error.' });
  }
});

// GET /api/admin/me: Verify token and return current admin
app.get('/api/admin/me', verifyAdminToken, (req, res) => {
  res.json({
    success: true,
    admin: req.admin
  });
});

// -------------------------------------------------------------
// Admin Protected Routes: Stats, CRUD, Moderation
// -------------------------------------------------------------

// GET /api/admin/stats: Dashboard Overview KPI
app.get('/api/admin/stats', verifyAdminToken, async (req, res) => {
  try {
    const totalStories = await storiesCollection.countDocuments();
    const totalComments = await commentsCollection.countDocuments();
    const totalCategories = await categoriesCollection.countDocuments();

    // Aggregating views and likes
    const aggregates = await storiesCollection.aggregate([
      {
        $group: {
          _id: null,
          totalViews: { $sum: '$views' },
          totalLikes: { $sum: '$likes' }
        }
      }
    ]).toArray();

    const totalViews = aggregates.length > 0 ? aggregates[0].totalViews : 0;
    const totalLikes = aggregates.length > 0 ? aggregates[0].totalLikes : 0;

    // Recent 5 stories
    const recentStories = await storiesCollection
      .find({})
      .sort({ createdAt: -1 })
      .limit(5)
      .toArray();

    // Recent 5 comments
    const recentComments = await commentsCollection
      .find({})
      .sort({ createdAt: -1 })
      .limit(5)
      .toArray();

    res.json({
      success: true,
      stats: {
        totalStories,
        totalViews,
        totalLikes,
        totalComments,
        totalCategories
      },
      recentStories,
      recentComments
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    res.status(500).json({ success: false, error: 'Failed to compute dashboard stats.' });
  }
});

// GET /api/admin/stories: Fetch all stories for admin table
app.get('/api/admin/stories', verifyAdminToken, async (req, res) => {
  try {
    const stories = await storiesCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      count: stories.length,
      data: stories
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve stories.' });
  }
});

// POST /api/stories: Create new biography
app.post('/api/stories', verifyAdminToken, async (req, res) => {
  try {
    const {
      title,
      slug,
      category,
      coverImage,
      summary,
      author = 'Editorial Staff',
      readingTime = '5 min read',
      content,
      milestones = [],
      featured = false
    } = req.body;

    if (!title || !category || !content) {
      return res.status(400).json({
        success: false,
        error: 'Title, category, and biography content are required.'
      });
    }

    // Auto-generate slug if not provided
    const cleanSlug = (slug || title)
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/(^-|-$)+/g, '');

    // Check duplicate slug
    const existing = await storiesCollection.findOne({ slug: cleanSlug });
    if (existing) {
      return res.status(400).json({
        success: false,
        error: `A biography with the slug "${cleanSlug}" already exists.`
      });
    }

    if (coverImage && !isSafeExternalHttpsUrl(coverImage)) {
      return res.status(400).json({
        success: false,
        error: 'Cover image must be a valid external HTTPS URL.'
      });
    }

    const newStory = {
      title: title.trim(),
      slug: cleanSlug,
      category: category.trim(),
      coverImage: coverImage || 'https://images.unsplash.com/photo-1457369804613-52c61a468e7d?auto=format&fit=crop&w=1200&q=80',
      summary: summary || title.trim(),
      author: author.trim(),
      readingTime: readingTime || '5 min read',
      content,
      milestones: Array.isArray(milestones) ? milestones : [],
      featured: Boolean(featured),
      views: 0,
      likes: 0,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await storiesCollection.insertOne(newStory);
    newStory._id = result.insertedId;

    // Ensure category exists in categoriesCollection
    try {
      const catName = newStory.category;
      const catSlug = catName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
      if (catSlug) {
        const catExists = await categoriesCollection.findOne({
          $or: [
            { name: { $regex: new RegExp(`^${catName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } },
            { slug: catSlug }
          ]
        });
        if (!catExists) {
          await categoriesCollection.insertOne({
            name: catName,
            slug: catSlug,
            description: `Biographies categorized under ${catName}.`,
            createdAt: new Date(),
            createdBy: req.admin?.username || 'admin'
          });
        }
      }
    } catch (catErr) {
      console.error('Non-critical error syncing category:', catErr);
    }

    res.status(201).json({
      success: true,
      message: 'Biography created successfully.',
      data: newStory
    });
  } catch (err) {
    console.error('Error creating story:', err);
    res.status(500).json({ success: false, error: 'Failed to create biography.' });
  }
});

// PUT /api/stories/:id: Update existing biography
app.put('/api/stories/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const query = buildStoryQuery(id);

    const updateFields = { ...req.body };
    delete updateFields._id; // Never overwrite MongoDB _id
    // Strip any MongoDB operator keys ($) to prevent operator injection
    Object.keys(updateFields).forEach((key) => {
      if (key.startsWith('$') || key.includes('.')) {
        delete updateFields[key];
      }
    });

    if (updateFields.coverImage && !isSafeExternalHttpsUrl(updateFields.coverImage)) {
      return res.status(400).json({
        success: false,
        error: 'Cover image must be a valid external HTTPS URL.'
      });
    }

    updateFields.updatedAt = new Date();

    if (updateFields.featured !== undefined) {
      updateFields.featured = Boolean(updateFields.featured);
    }

    const result = await storiesCollection.findOneAndUpdate(
      query,
      { $set: updateFields },
      { returnDocument: 'after' }
    );

    if (!result) {
      return res.status(404).json({ success: false, error: 'Biography not found to update.' });
    }

    // If category was updated, ensure it exists in categoriesCollection
    if (updateFields.category) {
      try {
        const catName = updateFields.category.trim();
        const catSlug = catName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
        if (catSlug) {
          const catExists = await categoriesCollection.findOne({
            $or: [
              { name: { $regex: new RegExp(`^${catName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') } },
              { slug: catSlug }
            ]
          });
          if (!catExists) {
            await categoriesCollection.insertOne({
              name: catName,
              slug: catSlug,
              description: `Biographies categorized under ${catName}.`,
              createdAt: new Date(),
              createdBy: req.admin?.username || 'admin'
            });
          }
        }
      } catch (catErr) {
        console.error('Non-critical error syncing category:', catErr);
      }
    }

    res.json({
      success: true,
      message: 'Biography updated successfully.',
      data: result
    });
  } catch (err) {
    console.error('Error updating story:', err);
    res.status(500).json({ success: false, error: 'Failed to update biography.' });
  }
});

// DELETE /api/stories/:id: Delete biography and associated comments
app.delete('/api/stories/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    const query = buildStoryQuery(id);

    const story = await storiesCollection.findOne(query);
    if (!story) {
      return res.status(404).json({ success: false, error: 'Biography not found.' });
    }

    // Delete story
    await storiesCollection.deleteOne({ _id: story._id });

    // Delete associated comments
    await commentsCollection.deleteMany({ storyId: story._id.toString() });

    res.json({
      success: true,
      message: 'Biography and related comments deleted successfully.'
    });
  } catch (err) {
    console.error('Error deleting story:', err);
    res.status(500).json({ success: false, error: 'Failed to delete biography.' });
  }
});

// GET /api/admin/comments: List all comments for moderation
app.get('/api/admin/comments', verifyAdminToken, async (req, res) => {
  try {
    const comments = await commentsCollection
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      count: comments.length,
      data: comments
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve comments.' });
  }
});

// DELETE /api/comments/:id: Moderation delete abusive comment
app.delete('/api/comments/:id', verifyAdminToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, error: 'Invalid comment ID.' });
    }

    const result = await commentsCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) {
      return res.status(404).json({ success: false, error: 'Comment not found.' });
    }

    res.json({
      success: true,
      message: 'Comment deleted successfully.'
    });
  } catch (err) {
    console.error('Error deleting comment:', err);
    res.status(500).json({ success: false, error: 'Failed to delete comment.' });
  }
});

// -------------------------------------------------------------
// Admin User & Role Management APIs
// -------------------------------------------------------------

// GET /api/admin/users: List all users and their admin/reader status
app.get('/api/admin/users', verifyAdminToken, async (req, res) => {
  try {
    const users = await usersCollection
      .find({})
      .sort({ createdAt: -1 })
      .project({ passwordHash: 0 })
      .toArray();

    res.json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to retrieve user directory.' });
  }
});

// POST /api/admin/make-admin: Promote any user to administrator
app.post('/api/admin/make-admin', verifyAdminToken, async (req, res) => {
  try {
    const { email, userId } = req.body;

    if (!email && !userId) {
      return res.status(400).json({ success: false, error: 'User email or userId is required.' });
    }

    const query = {};
    if (userId && ObjectId.isValid(userId)) {
      query._id = new ObjectId(userId);
    } else if (email) {
      query.email = email.trim().toLowerCase();
    } else {
      return res.status(400).json({ success: false, error: 'Invalid user lookup parameter.' });
    }

    const user = await usersCollection.findOne(query);
    if (!user) {
      return res.status(404).json({ success: false, error: 'No user account found matching provided criteria.' });
    }

    // 1. Update user role in usersCollection
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { role: 'admin', updatedAt: new Date() } }
    );

    // 2. Sync / upsert into adminsCollection so credentials work for both portal entry points
    await adminsCollection.updateOne(
      { username: user.email },
      {
        $set: {
          username: user.email,
          passwordHash: user.passwordHash,
          role: 'admin',
          userId: user._id.toString(),
          name: user.name,
          updatedAt: new Date()
        }
      },
      { upsert: true }
    );

    res.json({
      success: true,
      message: `User "${user.name}" (${user.email}) has been successfully granted administrator privileges!`,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: 'admin'
      }
    });
  } catch (err) {
    console.error('Make admin error:', err);
    res.status(500).json({ success: false, error: 'Failed to promote user to admin.' });
  }
});

// POST /api/admin/revoke-admin: Demote administrator to regular reader
app.post('/api/admin/revoke-admin', verifyAdminToken, async (req, res) => {
  try {
    const { email, userId } = req.body;

    if (!email && !userId) {
      return res.status(400).json({ success: false, error: 'User email or userId is required.' });
    }

    const query = {};
    if (userId && ObjectId.isValid(userId)) {
      query._id = new ObjectId(userId);
    } else if (email) {
      query.email = email.trim().toLowerCase();
    } else {
      return res.status(400).json({ success: false, error: 'Invalid user lookup parameter.' });
    }

    const user = await usersCollection.findOne(query);
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    // Safety guard: cannot demote self
    if (req.admin && (req.admin.id === user._id.toString() || req.admin.username === user.email)) {
      return res.status(400).json({ success: false, error: 'You cannot revoke your own administrator privileges.' });
    }

    // Update in usersCollection
    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { role: 'reader', updatedAt: new Date(), adminRevokedAt: new Date() } }
    );

    // Remove from adminsCollection
    await adminsCollection.deleteMany({
      $or: [
        { username: user.email },
        { username: user.email.toLowerCase() },
        { email: user.email }
      ]
    });

    res.json({
      success: true,
      message: `Admin privileges revoked for "${user.name}" (${user.email}).`,
      user: {
        id: user._id.toString(),
        name: user.name,
        email: user.email,
        role: 'reader'
      }
    });
  } catch (err) {
    console.error('Revoke admin error:', err);
    res.status(500).json({ success: false, error: 'Failed to revoke admin privileges.' });
  }
});

// POST /api/admin/bootstrap: Initial setup if NO admins exist anywhere in database
app.post('/api/admin/bootstrap', verifyUserToken, async (req, res) => {
  try {
    const totalAdmins = await adminsCollection.countDocuments();
    const totalAdminUsers = await usersCollection.countDocuments({
      role: { $in: ['admin', 'superadmin'] }
    });

    if (totalAdmins > 0 || totalAdminUsers > 0) {
      return res.status(403).json({
        success: false,
        error: 'Administrators are already configured. Please use an existing admin account to promote new admins.'
      });
    }

    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email of user to promote is required.' });
    }

    const user = await usersCollection.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found. Please register first.' });
    }

    await usersCollection.updateOne(
      { _id: user._id },
      { $set: { role: 'admin', updatedAt: new Date() } }
    );

    await adminsCollection.updateOne(
      { username: user.email },
      {
        $set: {
          username: user.email,
          passwordHash: user.passwordHash,
          role: 'admin',
          userId: user._id.toString(),
          name: user.name,
          createdAt: new Date()
        }
      },
      { upsert: true }
    );

    res.json({
      success: true,
      message: `Initial administrator established: "${user.name}" (${user.email}).`
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Bootstrap failed.' });
  }
});

// POST /api/seed: Manual trigger to re-seed initial data (Protected: Admin only)
app.post('/api/seed', verifyAdminToken, async (req, res) => {
  try {
    await categoriesCollection.deleteMany({});
    await categoriesCollection.insertMany(
      sampleCategories.map(c => ({
        ...c,
        createdAt: new Date()
      }))
    );

    await storiesCollection.deleteMany({});
    await commentsCollection.deleteMany({});
    await storiesCollection.insertMany(sampleStories);

    const steve = await storiesCollection.findOne({ slug: 'steve-jobs' });
    if (steve) {
      await commentsCollection.insertMany([
        {
          storyId: steve._id.toString(),
          name: 'Sarah Jenkins',
          comment: 'Steve Jobs changed how my entire generation interacts with typography and digital devices. Brilliant profile!',
          createdAt: new Date('2026-02-15T08:30:00Z')
        },
        {
          storyId: steve._id.toString(),
          name: 'Marcus Chen',
          comment: 'The quote about the intersection of technology and liberal arts still inspires my product design work every single day.',
          createdAt: new Date('2026-02-18T14:20:00Z')
        }
      ]);
    }

    res.json({
      success: true,
      message: `Database successfully re-seeded with ${sampleStories.length} profiles.`
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Failed to seed database.' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date(),
    database: db ? 'connected' : 'disconnected'
  });
});

// Catch-all 404 handler for unknown /api/* routes (prevents enumeration leakage)
app.use('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'API endpoint not found.'
  });
});

// Start Server
app.listen(PORT, async () => {
  console.log(`=========================================`);
  console.log(` Chronicle Magazine API Server Running`);
  console.log(` Port: http://localhost:${PORT}`);
  console.log(`=========================================`);
  await initializeDatabase();
});

