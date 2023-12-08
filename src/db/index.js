import mongoose from "mongoose";
import { DB_NAME } from "../constants.js";


const connectDB=async () =>{
    try {
        const connectionInstance=await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
        console.log(`\n mongo db connectecd !! dbhost ${connectionInstance.connection.host}`)
    } catch (error) {
        console.log("mongodb connnection error ",error)
        process.exit(1);
    }
}
export default connectDB;