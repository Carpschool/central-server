import { Module } from "@nestjs/common";
import { APP_GUARD } from "@nestjs/core";
import { MongooseModule } from "@nestjs/mongoose";
import { ThrottlerGuard, ThrottlerModule } from "@nestjs/throttler";
import { CentralController, WebhookController } from "./controllers";
import { SchoolSchema, ReplaySchema, UserSchema } from "./models";
import { SettingSchema, SettingsService } from "./settings";
import { SigningService } from "./security";
import { RegistryService } from "./registry";
import { AdminsService, ClerkUsers } from "./admins";
import { IdentityService, ClerkGuard, AdminGuard } from "./auth";
@Module({
  imports: [
    MongooseModule.forRootAsync({
      useFactory: () => ({ uri: process.env.MONGO_URI }),
    }),
    MongooseModule.forFeature([
      { name: "School", schema: SchoolSchema },
      { name: "Replay", schema: ReplaySchema },
      { name: "User", schema: UserSchema },
      { name: "Setting", schema: SettingSchema },
    ]),
    ThrottlerModule.forRoot([{ ttl: 60000, limit: 60 }]),
  ],
  controllers: [CentralController, WebhookController],
  providers: [
    SettingsService,
    SigningService,
    RegistryService,
    ClerkUsers,
    AdminsService,
    IdentityService,
    ClerkGuard,
    AdminGuard,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
  ],
})
export class AppModule {}
