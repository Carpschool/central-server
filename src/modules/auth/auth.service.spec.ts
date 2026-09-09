import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { AuthService } from './auth.service';
import { User } from './schemas/user.schema';

describe('AuthService', () => {
  let service: AuthService;

  const mockUserDoc = {
    _id: 'user_123',
    clerkUserId: 'user_clerk_abc',
    primaryEmail: 'student@ubc.ca',
    fullName: 'Jane Doe',
    phoneNumber: '+16045550199',
    lastLoginAt: new Date(),
  };

  const mockUserModel = {
    findOneAndUpdate: jest.fn(),
    findOne: jest.fn(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getModelToken(User.name),
          useValue: mockUserModel,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should synchronize user profile with MongoDB', async () => {
    mockUserModel.findOneAndUpdate.mockResolvedValue(mockUserDoc);

    const result = await service.syncUser('user_clerk_abc', {
      email: 'STUDENT@UBC.CA',
      fullName: 'Jane Doe',
      phoneNumber: '+16045550199',
    });

    expect(result).toBeDefined();
    expect(result.primaryEmail).toBe('student@ubc.ca');
    expect(mockUserModel.findOneAndUpdate).toHaveBeenCalledWith(
      { clerkUserId: 'user_clerk_abc' },
      expect.objectContaining({
        clerkUserId: 'user_clerk_abc',
        primaryEmail: 'student@ubc.ca',
        fullName: 'Jane Doe',
      }),
      { upsert: true, new: true },
    );
  });

  it('should find user by clerk id', async () => {
    mockUserModel.findOne.mockReturnValue({
      exec: jest.fn().mockResolvedValue(mockUserDoc),
    });

    const user = await service.getUserByClerkId('user_clerk_abc');
    expect(user).toBeDefined();
    expect(user?.fullName).toBe('Jane Doe');
    expect(mockUserModel.findOne).toHaveBeenCalledWith({ clerkUserId: 'user_clerk_abc' });
  });
});
