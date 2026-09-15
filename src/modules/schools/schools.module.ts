import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { School, SchoolSchema } from './schemas/school.schema';
import { SchoolsService } from './schools.service';
import { SchoolsController } from './schools.controller';
import { User, UserSchema } from '../auth/schemas/user.schema';
import { AdminGuard } from '../../common/guards/admin.guard';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: School.name, schema: SchoolSchema },
      { name: User.name, schema: UserSchema },
    ]),
  ],
  controllers: [SchoolsController],
  providers: [SchoolsService, AdminGuard],
  exports: [SchoolsService],
})
export class SchoolsModule {}
