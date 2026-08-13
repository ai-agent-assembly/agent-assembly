import createClient from "openapi-fetch";
import { getToken } from "../auth/tokenStorage";
import type { paths } from "./generated/schema";

export const api = createClient<paths>({
  baseUrl: import.meta.env.VITE_API_BASE_URL ?? "",
});

// Inject the stored JWT on every request.
api.use({
  onRequest({ request }) {
    const token = getToken();
    if (token) {
      request.headers.set("Authorization", `Bearer ${token}`);
    }
    return request;
  },
});
