import { object, string, TypeOf} from 'zod'

export const createUserSchema = object({
    body: object({
        firstName: string({
            required_error: "First name is required"
        }),
        lastName: string({
            required_error: "Last name is required"
        }),
        password: string({
            required_error: "Password is required"
        }).min(8, "Password is too short, must be atleast 8 chars long"),
        passwordConfirmation: string({
            required_error: "Password confirmation is required"
        }),
        email: string({
            required_error: "Email is required"
        }).email("Not a valid email")
    }).refine((data) => data.password === data.passwordConfirmation, {
        message: "Passwords do not match",
        path: ["passwordConfirmation"]
    })
})

export const verifyUserSchema = object({
    params: object({
        id: string(),
        verificationCode: string()
    })
    
})

export const forgotPasswordSchema = object({
    body: object({
        email: string({
            required_error: "Email is required"
        }).email("Not a valid email")
    })
})

export const resetPasswordSchema = object({
    params: object({
        id: string(),
        passwordResetCode: string()
    }),
    body: object({
        password: string({
            required_error: "Password is required"
        }).min(8, "Password is too short, must be atleast 8 chars long"),
        passwordConfirmation: string({
            required_error: "Password confirmation is required"
        }),
    }).refine((data) => data.password === data.passwordConfirmation, {
        message: "Passwords do not match",
        path: ["passwordConfirmation"]
    })
})

export type createUserInput = TypeOf<typeof createUserSchema>['body']

export type VerifyUserInput = TypeOf<typeof verifyUserSchema>['params']

export type forgotPasswordInput = TypeOf<typeof forgotPasswordSchema>['body']

export type resetPasswordInput = TypeOf<typeof resetPasswordSchema>

