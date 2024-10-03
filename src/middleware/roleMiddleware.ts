import { Request, Response, NextFunction } from "express";
import { JwtPayload } from "jsonwebtoken";

interface CustomJwtPayload extends JwtPayload {
  role?: string;
}

export const roleMiddleware = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = req.user as CustomJwtPayload;

    if (!user || !user.role || !roles.includes(user.role)) {
      return res.status(403).json({ error: "Acesso negado" });
    }

    next();
  };
};
