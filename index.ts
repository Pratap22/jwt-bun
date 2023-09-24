import express, { NextFunction, Request, Response } from "express";
import * as jose from "jose";

const app = express();
app.use(express.json());

const shops = [
  {
    name: "Kriti Grocery",
    username: "pratap",
  },
  {
    name: "Baskin Robbins",
    username: "madhav",
  },
  {
    name: "Annapurna Tech",
    username: "pratap",
  },
];

type User = {
  username: string;
  password: string;
};

interface JWTUser extends jose.JWTPayload {
  username: string;
}

interface JWTRequest extends Request {
  user?: JWTUser;
}

const users: User[] = [];
let refreshTokens: string[] = [];

// middleware

const checkAuth = async (
  req: JWTRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers["authorization"];
  const jwtToken = authHeader && authHeader.split(" ")[1];

  if (!jwtToken) {
    return res.sendStatus(401);
  }

  try {
    const { payload } = await jose.jwtVerify(
      jwtToken,
      new TextEncoder().encode(process.env.JWT_ACCESS_TOKEN_SECRET)
    );
    req.user = payload as User;
    next();
  } catch (error) {
    res.status(401).send("Error validating JWT token");
  }
};

app.get("/shops", checkAuth, (req: JWTRequest, res) => {
  res.json(shops.filter((shop) => shop.username === req.user?.username));
});

// Register

app.post("/register", (req, res) => {
  const { username, password } = req.body;
  users.push({ username, password });

  res.status(201).json({ username });
});

// Login

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = users.find((currUser) => currUser.username === username);

  if (!user) {
    return res.status(404).send("User not found");
  }

  if (user.password !== password) {
    return res.status(401).send("Invalid password");
  }

  const accessToken = await getToken({ username: user.username }, "15s");
  const refreshToken = await getToken({ username: user.username });
  refreshTokens.push(refreshToken);

  res.json({ accessToken, refreshToken });
});

// Refresh token

app.post("/refresh", async (req, res) => {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) {
    return res.status(401).send("Refresh token is missing");
  }

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).send("Refresh token not present in DB");
  }

  try {
    const { payload } = await jose.jwtVerify(
      refreshToken,
      new TextEncoder().encode(process.env.JWT_ACCESS_TOKEN_SECRET)
    );
    const accessToken = await getToken(payload, "15s");

    res.json({ accessToken });
  } catch (error) {
    res.status(401).send("Error with the refresh token");
  }
});

app.delete("/logout", checkAuth, (req, res) => {
  const jwtToken = req.body.token;
  refreshTokens = refreshTokens.filter((token) => token !== jwtToken);
  res.status(200).send("LoggedOut");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

const getToken = async (payload: jose.JWTPayload, expiry?: string) => {
  const signJwt = new jose.SignJWT(payload).setProtectedHeader({
    alg: "HS256",
  });

  if (expiry) {
    signJwt.setExpirationTime(expiry);
  }

  return await signJwt.sign(
    new TextEncoder().encode(process.env.JWT_ACCESS_TOKEN_SECRET)
  );
};
