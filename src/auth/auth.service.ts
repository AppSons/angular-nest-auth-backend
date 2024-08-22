import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';

import { JwtService } from '@nestjs/jwt';
import * as bcryptjs from 'bcryptjs';
import { User } from './entities/user.entity';

import { CreateUserDto, LoginDto, RegisterUserDto, UpdateAuthDto } from './dto';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name ) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      // Obtengo solo la contraseña
      const { password, ...userData } = createUserDto;
      //1- Encriptar la contraseña con hass de una vía con bcryptjs
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });     
         
      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();
      return user;

    } catch (error) {
      if(error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } ya existe`);
      }
      throw new InternalServerErrorException('Algún error a ocurrido!!!');
    }
  }
  async register( registerDto: RegisterUserDto): Promise<LoginResponse> {
    
    const user = await this.create(registerDto);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }





  async login( loginDto: LoginDto ): Promise<LoginResponse> {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if(!user) {
      throw new UnauthorizedException('Usuario-email no encontrado');
    }

    if(!bcryptjs.compareSync( password, user.password)) {
      throw new UnauthorizedException('Contraseña incorrecta');
    }

    const { password:_, ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getJwtToken({ id: user.id}),
    };

  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ){
    const user = await this.userModel.findById(id);
    const { password, ...rest} = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
