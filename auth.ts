import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import CredentialsProvider from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import { User } from './app/lib/definitions';
import bcrypt from 'bcrypt';

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [CredentialsProvider({
        async authorize(credentials) {
            const parsedCredentials = z
                .object({
                    email: z.string().min(6),
                    password: z.string().min(6),
                }).safeParse(credentials);

            if (parsedCredentials.success) {
                let { email, password } = parsedCredentials.data;
                let user = await getUser(email);
                if (!user) return null;

                let passwordMatched = await bcrypt.compare(password, user.password);
                if (passwordMatched) return user;
            }
            return null;
        },
    })],
});

async function getUser(email: string): Promise<User | undefined> {
    try {
        let user = await sql<User>`SELECT * FROM users WHERE email = ${email}`;
        return user.rows[0];
    } catch (error) {
        console.error('Failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
}