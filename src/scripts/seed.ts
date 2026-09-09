import * as mongoose from 'mongoose';
import * as nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';

/**
 * Database Seeder for Central Authority Server
 * 
 * Seeds default verified schools and configuration into central_db.
 * Run via: npm run seed
 */
async function seedDatabase() {
  const mongoUri = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/central_db';
  console.log(`Connecting to MongoDB at: ${mongoUri}`);

  await mongoose.connect(mongoUri);
  console.log('MongoDB connected successfully.');

  const db = mongoose.connection.db;
  if (!db) {
    throw new Error('Database connection object is undefined');
  }

  const schoolsCollection = db.collection('schools');

  // Generate deterministic keypair for seed testing if not provided
  const seedKeyPair = nacl.sign.keyPair();
  const seedPublicKey = naclUtil.encodeBase64(seedKeyPair.publicKey);
  const seedPrivateKey = naclUtil.encodeBase64(seedKeyPair.secretKey);

  console.log(`\nGenerated Seed School Ed25519 Keypair:`);
  console.log(`Public Key:  ${seedPublicKey}`);
  console.log(`Private Key: ${seedPrivateKey}\n`);

  const initialSchools = [
    {
      schoolCode: 'ubc',
      officialName: 'University of British Columbia',
      allowedEmailDomains: ['ubc.ca', 'alumni.ubc.ca', 'student.ubc.ca'],
      baseUrl: 'http://localhost:4001',
      ed25519PublicKey: seedPublicKey,
      isTrusted: true,
      campusLocation: {
        name: 'Vancouver Point Grey Campus',
        address: '2329 West Mall, Vancouver, BC V6T 1Z4',
        latitude: 49.2606,
        longitude: -123.246,
      },
      lastHeartbeat: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      schoolCode: 'sfu',
      officialName: 'Simon Fraser University',
      allowedEmailDomains: ['sfu.ca'],
      baseUrl: 'http://localhost:4002',
      ed25519PublicKey: seedPublicKey,
      isTrusted: true,
      campusLocation: {
        name: 'Burnaby Mountain Campus',
        address: '8888 University Dr, Burnaby, BC V5A 1S6',
        latitude: 49.2781,
        longitude: -122.9199,
      },
      lastHeartbeat: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  for (const school of initialSchools) {
    const existing = await schoolsCollection.findOne({ schoolCode: school.schoolCode });
    if (!existing) {
      await schoolsCollection.insertOne(school);
      console.log(`🌱 Seeded school: ${school.officialName} (${school.schoolCode})`);
    } else {
      console.log(`ℹ️  School ${school.schoolCode} already exists, skipping.`);
    }
  }

  console.log('Seeding completed successfully.');
  await mongoose.disconnect();
}

seedDatabase().catch((err) => {
  console.error('Seeding failed:', err);
  process.exit(1);
});
