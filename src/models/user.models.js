import mongoose from "mongoose";
import jwt, { Jwt } from "jsonwebtoken";
import bcrypt from "bcrypt"
const userSchema=new mongoose.Schema(
    {
        username:{
            type:String,
            required:true,
            index:true,//searchng space ko optimize karta hai
            lowercase:true,
            trim:true,
            unique:true
        },
        email:{
            type:String,
            required:true,
            lowercase:true,
            trim:true,
            unique:true
        },
        fullName:{
            type:String,
            required:true,
            index:true,//searchng space ko optimize karta hai
            // lowercase:true,
            trim:true,
        },
        avatar:{
            type:String,//cloudniary url
            required:true
        },
        coverimage:{
            type:String
        },
        watchHistory:{
            type:Schema.Types.ObjectId,
            ref:"Video"
        },
        password:{
            type:String,
            required:[true,"Password is required"]
        },
        refreshToken:{
            type:String
        }
    },{
        timestamps:true
    }
    );
    userSchema.pre("save",async function (next){
        if(!this.isModified("password")) return next();
        this.password=bcrypt.hash(this.password,next)
        next();
    })
    userSchema.methods.isPasswordCorrect = async function(password)
    {
        return await bcrypt.compare(password,this.password)
    }
    userSchema.methods.generateAcessToken=function(){
        return jwt.sign(
            {
                _id:this._id,
                email:this.email,
                username:this.username,
                fullName:this.fullName
            },
            process.env.ACCESS_TOKEN_SECRET,{
               expiresIn: process.env.ACCESS_TOKEN_EXPIRY 
            }
        )
    }
    userSchema.methods.generateRefreshToken=function(){
        return jwt.sign(
            {
                _id:this._id,
            },
            process.env.REFRESH_TOKEN_SECRET,{
               expiresIn: process.env.REFRESH_TOKEN_EXPIRY 
            }
        )
    }
export const User = mongoose.model("User",userSchema);