// env.d.ts
declare module "bun" {
    interface Env {
        PORT: string;
        SIGNATURE_HEADER_KEY: string;
        API_TOKEN: string;
        WEBHOOK_URL: string;
    }
}