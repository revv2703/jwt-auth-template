import { Request, Response } from "express";
import { VerifyUserInput, createUserInput, forgotPasswordInput, resetPasswordInput } from "../schema/user.schema";
import { createUser, findUserByEmail, findUserById } from "../service/user.service";
import sendEmail from "../utils/mailer";
import log from "../utils/logger";
import randomstring from 'randomstring'

export async function createUserHandler(req: Request<{}, {}, createUserInput>, res: Response) {
    const body = req.body

    try{
        const user = await createUser(body)

        await sendEmail({
            from: 'test@example.com',
            to: user.email,
            subject: 'Please verify your account',
            text: `Verification code ${user.verificationCode}\n Id: ${user._id}`
        })
        // 52:58 timestamp

        return res.send("User created successfully")
    }catch(e){
        if(e.code === 11000){
            return res.status(409).send("Account alerady exists")
        }
        return res.status(500).send(e)
    }
}

export async function verifyUserHandler(req: Request<VerifyUserInput>, res: Response) {
    const id = req.params.id
    const verificationCode = req.params.verificationCode

    const user = await findUserById(id)

    if(!user){
        return res.send("Could not verify user")
    }

    if(user.verified){
        return res.send("User is already verified")
    }

    if(user.verificationCode === verificationCode){
        user.verified = true

        await user.save()

        return res.send("User verified successfully")
    }

    return res.send("Could not verify user")
}

export async function forgotPasswordHandler(req: Request<forgotPasswordInput>, res: Response){

    const message = "If a user with tht email is registered, you will recieve a password reset link on you registered email id"
    const {email} = req.body

    const user = await findUserByEmail(email)

    if(!user){
        log.debug(`User with emil ${email} does not exist`)
        return res.send(message)
    }

    if(!user.verified){
        return res.send("User is not verified")
    }

    const passwordResetCode = randomstring.generate()

    user.passwordResetCode = passwordResetCode
    await user.save()

    await sendEmail({
        to: user.email,
        from: "test@example.com",
        subject: "Reset password link",
        text: `Password reset code: ${passwordResetCode}\n Id: ${user._id}`
    })

    log.debug(`Password reset email sent to ${email}`)

    return res.send(message)
}

export async function resetPasswordHandler(req: Request<resetPasswordInput["params"], {}, resetPasswordInput["body"]>, res: Response) {
    const { id, passwordResetCode } = req.params
    const { password } = req.body

    const user = await findUserById(id)

    if (!user || !user.passwordResetCode || user.passwordResetCode !== passwordResetCode) {
        return res.status(400).send("Could not reset user password")
    }

    user.passwordResetCode = null

    user.password = password

    await user.save()
    return res.send("Password reset successful")
    await user.save()

    return res.send("Password reset successful")
}

export async function getCurrentUserHandler(req: Request, res: Response) {
    return res.send(res.locals.user)
}