import mongoose from 'mongoose'
import config from 'config'
import log from './logger'

async function connectdb(){
    const dbUri = config.get<string>("dbUri")

    try{
        await mongoose.connect(dbUri)
        log.info("Connected to DB")
    }catch(e){
        process.exit(1)
    }
}

export default connectdb;