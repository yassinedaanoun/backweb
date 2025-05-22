import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import * as bcrypt from "https://deno.land/x/bcrypt@v0.4.1/mod.ts";
import { JWTPayload, SignJWT, jwtVerify } from "npm:jose@5.9.6";
import { oakCors } from "https://deno.land/x/cors/mod.ts";
import { Client } from "https://deno.land/x/postgres@v0.17.0/mod.ts";


const app = new Application();
const router = new Router();
const port = Deno.args[0] ? Number(Deno.args[0]) : 3000;

// JWT secret
const secret = new TextEncoder().encode("ed5a207a8e88013ab968eaf43d0017507508e5efa2129248b713a223eaf66864");

// Create JWT
async function createJWT(payload: JWTPayload): Promise<string> {
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("1h")
    .sign(secret);
  console.log("Token généré :", token);
  return token;
}

// Initialize PostgreSQL client
const client = new Client({
  user: "yassinedaanoun", // Utilisez votre rôle PostgreSQL
  database: "userdb", // Nom de la base de données
  hostname: "localhost",
  password: "", // Laissez vide si aucun mot de passe n'est défini
  port: 65432,
});

try {
  await client.connect();
  console.log("✅ Connected to the database successfully.");
} catch (error) {
  console.error("❌ Failed to connect to the database:", error);
  Deno.exit(1); // Arrête le serveur si la connexion échoue
}
// Disable NOTICE messages
await client.queryObject(`SET client_min_messages TO WARNING;`);
// Create the table if it doesn't exist
await client.queryObject(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
  );
`);

// Create the dictionnaire table if it doesn't exist
await client.queryObject(`
  CREATE TABLE IF NOT EXISTS dictionnaire (
    id SERIAL PRIMARY KEY,
    mot TEXT UNIQUE NOT NULL
  );
`);

// Créer la table des scores
await client.queryObject(`
  CREATE TABLE IF NOT EXISTS player_scores (
    username TEXT PRIMARY KEY REFERENCES users(username),
    current_score INTEGER DEFAULT 0,
    max_score INTEGER DEFAULT 0,
    games_played INTEGER DEFAULT 0
  );
`);

// Créer la table des parties
await client.queryObject(`
  CREATE TABLE IF NOT EXISTS games (
    game_id UUID PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    player_count INTEGER NOT NULL
  );
`);

// Créer la table des manches
await client.queryObject(`
  CREATE TABLE IF NOT EXISTS game_rounds (
    round_id SERIAL PRIMARY KEY,
    game_id UUID NOT NULL REFERENCES games(game_id),
    round_number INTEGER NOT NULL,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    drawer TEXT NOT NULL REFERENCES users(username),
    word TEXT,
    correct_guessers INTEGER DEFAULT 0,
    UNIQUE(game_id, round_number)
  );
`);

await client.queryObject(`
  DO $$
  BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='users' AND column_name='role') THEN
      ALTER TABLE users ADD COLUMN role TEXT;
    END IF;
  END;
  $$;
`);

await client.queryObject(`
  UPDATE users SET role = 'admin' WHERE username = 'admin';
`);

// Ajouter ces variables globales
let currentWord: string | null = null;
let correctGuessers: string[] = []; // Ordre des joueurs qui ont deviné
let playerScores: Map<string, number> = new Map(); // Stockage des scores
let currentRound = 1; // Commencer à 1 au lieu de 0
const TOTAL_ROUNDS = 3;

// Ajouter cette fonction pour gérer les scores persistants
async function updatePlayerScore(username: string, addedPoints: number) {
  try {
    // Vérifier si le joueur existe dans la table des scores
    const checkResult = await client.queryObject(
      "SELECT * FROM player_scores WHERE username = $1;",
      [username]
    );
    
    if (checkResult.rows.length === 0) {
      // Créer une entrée pour ce joueur
      await client.queryObject(
        "INSERT INTO player_scores (username, current_score, max_score, games_played) VALUES ($1, $2, $2, 1);",
        [username, addedPoints]
      );
    } else {
      // Mettre à jour le score du joueur
      const currentRow = checkResult.rows[0];
      const newCurrentScore = (currentRow.current_score as number) + addedPoints;
      const newMaxScore = Math.max(newCurrentScore, currentRow.max_score as number);
      
      await client.queryObject(
        "UPDATE player_scores SET current_score = $1, max_score = $2, games_played = games_played + 1 WHERE username = $3;",
        [newCurrentScore, newMaxScore, username]
      );
    }
  } catch (error) {
    console.error("Erreur lors de la mise à jour du score:", error);
  }
}

// Middleware pour vérifier si l'utilisateur est un administrateur
const adminMiddleware = async (ctx: any, next: any) => {
    try {
        const authHeader = ctx.request.headers.get("Authorization");

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            ctx.response.status = 401;
            ctx.response.body = { message: "Token manquant ou invalide" };
            return;
        }

        const token = authHeader.split(" ")[1]; // Récupère le token après "Bearer"

        const { payload } = await jwtVerify(token, secret, {
            algorithms: ["HS256"], // Assurez-vous que l'algorithme correspond à celui utilisé pour signer
        });

        if (payload.role !== "admin") {
            ctx.response.status = 403;
            ctx.response.body = { message: "Accès interdit : admin uniquement" };
            return;
        }

        ctx.state.username = payload.username; // Stocker le nom d'utilisateur dans le contexte
        await next();
    } catch (err) {
        console.error("❌ Erreur lors de la vérification du token :", err);
        ctx.response.status = 401;
        ctx.response.body = { message: "Token invalide" };
    }
};

// Routes
router.post("/register", async (ctx) => {
  const body = await ctx.request.body({ type: "json" }).value;
  const { username, password } = body;

  // Check if the user already exists
  const existingUser = await client.queryObject(
    "SELECT * FROM users WHERE username = $1",
    [username]
  );

  if (existingUser.rows.length > 0) {
    ctx.response.status = 409;
    ctx.response.body = { message: "User already exists" };
    return;
  }

  // Hash the password and insert the user
  const hashedPassword = await bcrypt.hash(password);
  await client.queryObject(
    "INSERT INTO users (username, password) VALUES ($1, $2)",
    [username, hashedPassword]
  );

  ctx.response.status = 201;
  ctx.response.body = { message: "User registered successfully" };
});

router.post("/login", async (ctx) => {
  console.log("🔍 Tentative de connexion...");
  const body = await ctx.request.body({ type: "json" }).value;
  const { username, password } = body;

  console.log("Données reçues :", { username, password });

  const result = await client.queryObject(
      "SELECT * FROM users WHERE username = $1",
      [username]
  );

  if (result.rows.length > 0) {
      const user = result.rows[0];
      console.log("✅ Utilisateur trouvé :", user);

      const passwordMatch = await bcrypt.compare(password, user.password);
      console.log("🔑 Mot de passe valide :", passwordMatch);

      if (passwordMatch) {
          const token = await createJWT({ 
              username: user.username,
              role: user.role 
          });

          console.log("🔐 Token généré :", token);

          ctx.response.status = 200;
          ctx.response.body = { 
              message: "Login successful", 
              username: user.username,
              role: user.role,
              token: token
          };
          return;
      }
  }

  console.log("❌ Connexion échouée : nom d'utilisateur ou mot de passe invalide");
  ctx.response.status = 401;
  ctx.response.body = { message: "Invalid username or password" };
});

router.post("/populate-dictionnaire", async (ctx) => {
  const body = await ctx.request.body({ type: "json" }).value;
  const { mots } = body; // Les mots doivent être envoyés sous forme de tableau

  try {
    for (const mot of mots) {
      await client.queryObject(
        "INSERT INTO dictionnaire (mot) VALUES ($1) ON CONFLICT (mot) DO NOTHING;",
        [mot]
      );
    }
    ctx.response.status = 200;
    ctx.response.body = { message: "Dictionnaire peuplé avec succès" };
  } catch (error) {
    console.error("Erreur lors de l'insertion des mots :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur lors de l'insertion des mots" };
  }
});

router.get("/get-random-words", async (ctx) => {
  try {
    const result = await client.queryObject<{ mot: string }>(
      "SELECT mot FROM dictionnaire ORDER BY RANDOM() LIMIT 4;"
    );
    ctx.response.status = 200;
    ctx.response.body = result.rows; // Renvoie les mots sous forme de tableau
  } catch (error) {
    console.error("Erreur lors de la récupération des mots :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur lors de la récupération des mots" };
  }
});

// Ajouter une route pour récupérer les meilleurs scores
router.get("/highscores", async (ctx) => {
  try {
    const result = await client.queryObject(
      "SELECT username, max_score FROM player_scores ORDER BY max_score DESC LIMIT 10;"
    );
    
    ctx.response.body = { highscores: result.rows };
  } catch (error) {
    console.error("Erreur lors de la récupération des meilleurs scores:", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour lister les utilisateurs
router.get("/admin/users", adminMiddleware, async (ctx) => {
  console.log("🔍 Requête reçue pour /admin/users");
  try {
    const result = await client.queryObject("SELECT username, role FROM users;");
    console.log("✅ Utilisateurs récupérés :", result.rows);
    ctx.response.body = { users: result.rows };
  } catch (error) {
    console.error("❌ Erreur lors de la récupération des utilisateurs :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour supprimer un utilisateur
router.delete("/admin/users/:username", adminMiddleware, async (ctx) => {
  const username = ctx.params.username;

  try {
    // D'abord supprimer les scores du joueur
    await client.queryObject("DELETE FROM player_scores WHERE username = $1;", [username]);
    
    // Ensuite supprimer l'utilisateur
    await client.queryObject("DELETE FROM users WHERE username = $1;", [username]);
    
    ctx.response.body = { message: `Utilisateur ${username} supprimé.` };
  } catch (error) {
    console.error("Erreur lors de la suppression de l'utilisateur :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur lors de la suppression" };
  }
});

// Route pour lister les scores des joueurs
router.get("/admin/scores", adminMiddleware, async (ctx) => {
  try {
    const result = await client.queryObject(
      "SELECT username, current_score, max_score, games_played FROM player_scores ORDER BY max_score DESC;"
    );
    ctx.response.body = { scores: result.rows };
  } catch (error) {
    console.error("Erreur lors de la récupération des scores :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour réinitialiser les scores d'un joueur
router.put("/admin/scores/:username/reset", adminMiddleware, async (ctx) => {
  const username = ctx.params.username;

  try {
    await client.queryObject(
      "UPDATE player_scores SET current_score = 0, games_played = 0 WHERE username = $1;",
      [username]
    );
    ctx.response.body = { message: `Scores de ${username} réinitialisés.` };
  } catch (error) {
    console.error("Erreur lors de la réinitialisation des scores :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour ajouter un mot au dictionnaire
router.post("/admin/dictionnaire", adminMiddleware, async (ctx) => {
  const body = await ctx.request.body({ type: "json" }).value;
  const { mot } = body;

  try {
    await client.queryObject(
      "INSERT INTO dictionnaire (mot) VALUES ($1) ON CONFLICT (mot) DO NOTHING;",
      [mot]
    );
    ctx.response.body = { message: `Mot "${mot}" ajouté au dictionnaire.` };
  } catch (error) {
    console.error("Erreur lors de l'ajout du mot :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour supprimer un mot du dictionnaire
router.delete("/admin/dictionnaire/:mot", adminMiddleware, async (ctx) => {
  const mot = ctx.params.mot;

  try {
    await client.queryObject("DELETE FROM dictionnaire WHERE mot = $1;", [mot]);
    ctx.response.body = { message: `Mot "${mot}" supprimé du dictionnaire.` };
  } catch (error) {
    console.error("Erreur lors de la suppression du mot :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour lister les mots du dictionnaire
router.get("/admin/dictionnaire", adminMiddleware, async (ctx) => {
  try {
    const result = await client.queryObject("SELECT mot FROM dictionnaire;");
    ctx.response.body = { mots: result.rows };
  } catch (error) {
    console.error("Erreur lors de la récupération des mots :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour rechercher un mot dans le dictionnaire
router.get("/admin/dictionnaire/search/:mot", adminMiddleware, async (ctx) => {
  const mot = ctx.params.mot;

  try {
    const result = await client.queryObject(
      "SELECT * FROM dictionnaire WHERE mot = $1;",
      [mot]
    );

    if (result.rows.length > 0) {
      ctx.response.body = { exists: true, message: `Le mot "${mot}" existe dans le dictionnaire.` };
    } else {
      ctx.response.body = { exists: false, message: `Le mot "${mot}" n'existe pas dans le dictionnaire.` };
    }
  } catch (error) {
    console.error("Erreur lors de la recherche du mot :", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

// Route pour voir les statistiques globales
router.get("/admin/stats", adminMiddleware, async (ctx) => {
  try {
    const userCountResult = await client.queryObject("SELECT COUNT(*) AS count FROM users;");
    const gameCountResult = await client.queryObject("SELECT COUNT(*) AS count FROM games;");
    const wordCountResult = await client.queryObject("SELECT COUNT(*) AS count FROM dictionnaire;");

    // Convertir BigInt en Number pour éviter l'erreur de sérialisation
    const userCount = Number(userCountResult.rows[0]?.count || 0);
    const gameCount = Number(gameCountResult.rows[0]?.count || 0);
    const wordCount = Number(wordCountResult.rows[0]?.count || 0);

    ctx.response.body = {
      users: userCount,
      games: gameCount,
      words: wordCount,
    };
  } catch (error) {
    console.error("Erreur lors de la récupération des statistiques:", error);
    ctx.response.status = 500;
    ctx.response.body = { message: "Erreur serveur" };
  }
});

const clients = new Map<WebSocket, string>(); // Map pour associer WebSocket à un utilisateur
let currentDrawer: string | null = null; // Stocke le joueur actuel qui dessine

async function sendWordsToDrawer() {
  if (currentDrawer) {
    const result = await client.queryObject<{ mot: string }>(
      "SELECT mot FROM dictionnaire ORDER BY RANDOM() LIMIT 4;"
    );
    const words = result.rows.map(row => row.mot);

    // Envoyer les mots uniquement au dessinateur
    for (const [client, username] of clients) {
      if (username === currentDrawer && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({ type: "words", words }));
      }
    }
  }
}

// Modifier la fonction chooseRandomDrawer pour limiter les manches correctement
function chooseRandomDrawer(isNewRound = false) {
  // Array of all connected clients (usernames)
  const userArray = Array.from(clients.values());
  
  if (userArray.length === 0) {
    console.log("❌ No connected users to choose from.");
    return;
  }
  
  // Incrémenter la manche uniquement lorsque demandé
  if (isNewRound) {
    if (currentRound < TOTAL_ROUNDS) {
      currentRound++;
      console.log(`🔄 Starting round ${currentRound}/${TOTAL_ROUNDS}`);
    } else {
      console.log("Toutes les manches sont terminées");
      // Envoyer un message de fin de partie à tous les clients
      broadcastMessage({
        type: "game_over",
        scores: Object.fromEntries(playerScores)
      });
      return; // Ne pas choisir de nouveau dessinateur
    }
  }
  
  // Get a random index from the array
  const randomIndex = Math.floor(Math.random() * userArray.length);
  
  // Set the new drawer
  currentDrawer = userArray[randomIndex];
  console.log(`🎨 New drawer selected: ${currentDrawer}`);
  
  // Notify all clients about the new drawer and current round
  for (const [socket, username] of clients.entries()) {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({
        type: "drawer",
        username: currentDrawer,
        isNewRound: isNewRound,
        currentRound: currentRound
      }));
    }
  }
}

function broadcastMessage(message: any) {
  for (const [client, _] of clients) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(message));
    }
  }
}

router.get("/ws", (ctx) => {
  const socket = ctx.upgrade();

  socket.onopen = () => {
    console.log("Client connecté");
    
    // Initialiser le score à 0 pour les nouveaux joueurs
    socket.onmessage = async (event) => {
      const message = JSON.parse(event.data);
      
      if (message.type === "login") {
        const username = message.username;
        clients.set(socket, username);
        
        // Initialiser le score si c'est un nouveau joueur
        if (!playerScores.has(username)) {
          playerScores.set(username, 0);
        }
        
        console.log(`👤 ${username} connecté.`);
        
        // Envoyer les scores actuels au joueur
        socket.send(JSON.stringify({
          type: "scores",
          scores: Object.fromEntries(playerScores)
        }));
        
        // Choisir un dessinateur si c'est le premier joueur
        if (clients.size === 1) {
          chooseRandomDrawer();
        }
      } else if (message.type === "chat") {
        const username = clients.get(socket);
        if (username) {
          let isCorrectGuess = false;
          
          // Vérifier si c'est le bon mot
          if (username !== currentDrawer && 
              currentWord && 
              message.message.trim().toLowerCase() === currentWord.toLowerCase()) {
            
            isCorrectGuess = true;
            
            if (!correctGuessers.includes(username)) {
              correctGuessers.push(username);
              
              // Attribution des points
              let pointsAwarded = 0;
              switch (correctGuessers.length) {
                case 1: pointsAwarded = 600; break;
                case 2: pointsAwarded = 450; break;
                case 3: pointsAwarded = 300; break;
                default: pointsAwarded = 100;
              }
              
              // Mise à jour des scores
              const currentScore = playerScores.get(username) || 0;
              playerScores.set(username, currentScore + pointsAwarded);
              await updatePlayerScore(username, pointsAwarded);
              
              broadcastMessage({
                type: "scores",
                scores: Object.fromEntries(playerScores)
              });
            }
            
            // Envoyer un message différent à chaque client pour une bonne réponse
            for (const [clientSocket, clientName] of clients) {
              if (clientSocket.readyState === WebSocket.OPEN) {
                const chatMessage = { 
                  type: "chat", 
                  username, 
                  // Afficher le vrai message uniquement à l'expéditeur
                  message: clientName === username ? message.message : "a deviné",
                  isCorrectGuess 
                };
                
                clientSocket.send(JSON.stringify(chatMessage));
              }
            }
          } else {
            // Message normal - diffuser à tous
            broadcastMessage({
              type: "chat",
              username,
              message: message.message,
              isCorrectGuess
            });
          }
        }
      } else if (message.type === "word_selected") {
        // Enregistrer le mot sélectionné
        currentWord = message.word;
        console.log(`Mot sélectionné : ${currentWord}`);
        
        const username = clients.get(socket);
        if (username === currentDrawer) {
          // Envoyer un message avec le type word_selected à tous les clients
          broadcastMessage({ 
            type: "word_selected"
          });
          
          // Réinitialiser la liste des joueurs qui ont deviné correctement
          correctGuessers = [];
          
          // Démarrer un timer côté serveur
          setTimeout(() => {
            if (currentWord) {  // Vérifier que le mot existe toujours
              broadcastMessage({
                type: "time_up",
                word: currentWord,
                correctGuessers: correctGuessers,
                scores: Object.fromEntries(playerScores) 
              });
              
              // Réinitialiser le mot actuel
              currentWord = null;
              
              // Ne plus appeler chooseRandomDrawer ici - c'est le client qui envoie next_round
            }
          }, 60000); // 60 secondes
        }
      } else if (message.type === "time_up") {
        broadcastMessage({
          type: "time_up",
          word: currentWord,
          correctGuessers: correctGuessers,
          scores: Object.fromEntries(playerScores)
        });
        
        // Réinitialiser pour le prochain tour
        currentWord = null;
        correctGuessers = [];
      } else if (message.type === "draw" || message.type === "clear") {
        const username = clients.get(socket);
        if (username === currentDrawer) {
          for (const [client, _] of clients) {
            if (client !== socket && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify(message));
            }
          }
        }
      } else if (message.type === "new_game") {
        // Réinitialiser le compteur de manche au début d'une nouvelle partie
        currentRound = 1;
        
        // Réinitialiser les scores si nécessaire
        playerScores.clear();
        
        // Choisir un premier dessinateur
        chooseRandomDrawer(false);
      } else if (message.type === "end_game") {
        const username = clients.get(socket);
        if (username) {
          console.log(`${username} a quitté la partie.`);
          clients.delete(socket); // Supprimer le joueur de la liste des clients
        }
      } else if (message.type === "next_round") {
        // Choisir un nouveau dessinateur pour la prochaine manche
        chooseRandomDrawer(true);
      } else if (message.type === "game_over") {
        // Réinitialiser le compteur de manches
        currentRound = 0;

        // Sauvegarder les scores finaux si nécessaire
        console.log("Game over. Scores:", Object.fromEntries(playerScores));
      }
    };
  };

  socket.onclose = () => {
    const username = clients.get(socket);
    clients.delete(socket);
    console.log(`❌ ${username} s'est déconnecté.`);
    if (username === currentDrawer) {
      chooseRandomDrawer(); // Choisir un nouveau dessinateur si le dessinateur actuel se déconnecte
    }
  };
});

// Apply CORS middleware
app.use(oakCors({
  origin: ["http://localhost:5500", "http://127.0.0.1:5500", "http://127.0.0.1:5501"],
  credentials: true, // Autoriser l'envoi des cookies
}));

app.use(router.routes());
app.use(router.allowedMethods());

// Example usage of the fetch function
fetch("http://localhost:3000/admin/dictionnaire/search/someWord", {
    method: "GET",
    credentials: "include", // Inclure les cookies
});

console.log(`Oak server running on port ${port}`);
await app.listen({ port });