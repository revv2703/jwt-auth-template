import { Request, Response } from "express";
import { createSessionInput } from "../schema/auth.schema";
import { findUserByEmail, findUserById } from "../service/user.service";
import { findSessionById, signAccessToken, signRefreshToken } from "../service/auth.service";
import { get } from "lodash";
import { verifyJwt } from "../utils/jwt";


export async function createSessionHandler(req: Request<{}, {}, createSessionInput>, res: Response) {
    const {email, password} = req.body

    const user = await findUserByEmail(email)

    if(!user){
        return res.send("User not registered")
    }

    if(!user.verified){
        return res.send("Please verify your email")
    }

    const isValid = await user.validatePassword(password)

    if(!isValid){
        return res.send("Invalid email or password")
    }

    const accessToken = signAccessToken(user)

    const refreshToken = await signRefreshToken({userId: user._id.toString()})

    return res.send({
        accessToken, refreshToken
    })
}

export async function refreshAccessTokenHandler(req: Request, res: Response) {
    const refreshToken = req.headers['x-refresh']?.toString() ?? '';


    const decoded = verifyJwt<{session: string}>(refreshToken, "refreshTokenPublicKey")

    if(!decoded){
        return res.status(401).send("Could not refresh access token(Could not verify JWT))")
    }

    const session = await findSessionById(decoded.session)

    if(!session || !session.valid){
        return res.status(401).send("Could not refresh access token(Invalid Session)")
    }

    const user = await findUserById(String(session.user))

    if(!user){
        return res.status(401).send("Could not refresh access token(Usernot found)")
    }

    const accessToken = signAccessToken(user)

    return res.send({accessToken})
}