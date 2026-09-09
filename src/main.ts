import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const logger = new Logger('CentralServerBootstrap');
  const app = await NestFactory.create(AppModule);

  // Enable CORS for web client and mobile clients
  app.enableCors({
    origin: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  // Global DTO validation with class-validator
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  // Configure Swagger OpenAPI interactive documentation
  const config = new DocumentBuilder()
    .setTitle('Carpschool Central Authority Server API')
    .setDescription(
      'REST API documentation for Carpschool Central Server. Manages global Clerk user identities, Ed25519 school directory trust, and Federation Ticket issuance.',
    )
    .setVersion('2.0.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  const port = process.env.PORT || 4000;
  await app.listen(port);

  logger.log(`🚀 Central Server running on http://localhost:${port}`);
  logger.log(`📚 Swagger API Documentation available at http://localhost:${port}/api/docs`);
}

bootstrap();
