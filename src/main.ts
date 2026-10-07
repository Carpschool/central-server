import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import { ConsoleLogger, ValidationPipe } from "@nestjs/common";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import helmet from "helmet";
import { AppModule } from "./app.module";
import { validateEnv } from "./config";
import { SettingsService } from "./settings";
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
  const settings = app.get(SettingsService);
  await settings.get();
  app.enableCors({
    // Web origins live in DB settings (network admin edits them); 5s cache.
    origin: (o, cb) => cb(null, !!o && settings.peek().corsOrigins.includes(o)),
    credentials: false,
  });
  if (!(await settings.get()).publicUrl)
    console.warn("Central publicUrl not set: run  node scripts/settings.mjs publicUrl=https://... corsOrigins=https://web...  (then edit in web)");
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
