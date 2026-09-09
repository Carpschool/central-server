import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { CryptoModule } from './modules/crypto/crypto.module';
import { SchoolsModule } from './modules/schools/schools.module';
import { AuthModule } from './modules/auth/auth.module';
import { EmailModule } from './modules/email/email.module';

/**
 * AppModule
 * 
 * Root NestJS module for the Carpschool Central Authority Server.
 * Configures environment variables, connects to the isolated central_db MongoDB instance,
 * and aggregates feature modules.
 */
@Module({
  imports: [
    // Global environment configuration
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env', '.env.local'],
    }),

    // Mongoose MongoDB connection (isolated internal container network, no auth)
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>(
          'MONGO_URI',
          'mongodb://central-mongo:27017/central_db',
        ),
      }),
      inject: [ConfigService],
    }),

    // Core domain modules
    CryptoModule,
    SchoolsModule,
    AuthModule,
    EmailModule,
  ],
})
export class AppModule {}
