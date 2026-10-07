import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ConsoleLogger, ValidationPipe } from "@nestjs/common";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import helmet from "helmet";
import { AppModule } from "./app.module";
import { required, validateEnv } from "./config";
async function bootstrap() {
  validateEnv();
  const app = await NestFactory.create(AppModule, {
    rawBody: true,
    logger: new ConsoleLogger("central", { json: true }),
    bodyParser: true,
  });
  app.use(helmet());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.enableCors({
    origin: required("CLERK_AUTHORIZED_PARTIES")
      .split(",")
      .map((s) => s.trim()),
    credentials: false,
  });
  SwaggerModule.setup(
    "docs",
    app,
    SwaggerModule.createDocument(
      app,
      new DocumentBuilder()
        .setTitle("Carpschool central")
        .setVersion("3.0")
        .addBearerAuth()
        .build(),
    ),
  );
  app.enableShutdownHooks();
  await app.listen(Number(process.env.PORT || 3101), "0.0.0.0");
}
bootstrap().catch((error) => {
  console.error("Central startup failed:", error.message);
  process.exit(1);
});
