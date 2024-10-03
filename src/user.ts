import express, { Request, Response } from "express";
import { authMiddleware } from "./middleware/authMiddleware";
import { roleMiddleware } from "./middleware/roleMiddleware";

const router = express.Router();

router.get(
  "/dashboard",
  authMiddleware,
  roleMiddleware(["user", "admin"]),
  (req: Request, res: Response) => {
    res.json({ message: "Conteúdo do dashboard", user: req.user });
  }
);

router.get(
  "/profile",
  authMiddleware,
  roleMiddleware,
  (req: Request, res: Response) => {
    res.json({ messagem: "Seu perfil", user: req.user });
  }
);

router.get(
  "/admin",
  authMiddleware,
  roleMiddleware(["admin"]),
  (req: Request, res: Response) => {
    res.json({
      message: "Conteúdo exclusivo para administradores",
      user: req.user,
    });
  }
);

router.get(
  "/admin-reports",
  authMiddleware,
  roleMiddleware(["admin"]),
  (req: Request, res: Response) => {
    res.json({
      message: "Relatórios exclusivos para administradores",
      user: req.user,
    });
  }
);

export default router;
