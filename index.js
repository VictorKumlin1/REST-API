const express = require("express");
const mysql = require("mysql");
const app = express();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const port = 3000;

app.get('/', (req, res) => {
  const info = `
    <html>
      <head>
        <title>Välkommen till API:et</title>
      </head>
      <body>
        <h1>Välkommen till API:et!</h1>
        <h2>Rutter:</h2>
        <ul>
          <li><strong>GET /user</strong>: Returnerar en lista av alla användare</li>
          <li><strong>GET /user/:id</strong>: Returnerar en specifik användare baserat på ID</li>
          <li><strong>POST /user</strong>: Skapar en ny användare</li>
          <li><strong>PUT /user/:id</strong>: Uppdaterar en befintlig användare baserat på ID</li>
          <li><strong>POST /login</strong>: Loggar in och returnerar en JWT-token</li>
          <li><strong>GET /protected</strong>: Skyddad route som kräver JWT-token för åtkomst</li>
        </ul>
      </body>
    </html>
  `;
  res.send(info);
});


app.use(express.json());

function generateToken(userId) {
  return jwt.sign({ userId }, "secret_key", { expiresIn: "1h" });
}

function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  jwt.verify(token, "secret_key", (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
    req.userId = decoded.userId;
    next();
  });
}


async function getDBConnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "", // Lösenord för din databas
    database: "databas"
  });
}

// GET /user - returnerar en lista av alla användare
app.get('/user', async (req, res) => {
  try {
    const connection = await getDBConnection();
    connection.query('SELECT * FROM users', (err, results) => {
      connection.end(); // Avsluta anslutningen efter användning
      if (err) {
        console.error('Error fetching users: ' + err.stack);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
      res.json(results);
    });
  } catch (error) {
    console.error('Database connection error: ' + error.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /user/:id - returnerar en användare angivet av det id som angivits.
app.get('/user/:id', async (req, res) => {
  try {
    const connection = await getDBConnection();
    const id = parseInt(req.params.id);
    connection.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
      connection.end(); // Avsluta anslutningen efter användning
      if (err) {
        console.error('Error fetching user: ' + err.stack);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
      if (results.length === 0) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      res.json(results[0]);
    });
  } catch (error) {
    console.error('Database connection error: ' + error.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /user - Skapar en ny användare
app.post('/user', async (req, res) => {
  try {
    const newUser = req.body;
    const connection = await getDBConnection();
    connection.query('INSERT INTO users SET ?', newUser, (err, result) => {
      connection.end();
      if (err) {
        console.error('Error creating user:', err);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }

      const createdUserId = result.insertId;
      const createdUser = { id: createdUserId, ...newUser };
      res.status(201).json(createdUser);
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /user/:id - Uppdaterar en användare angivet av det id som angivits.
app.put('/user/:id', async (req, res) => {
  try {
    const connection = await getDBConnection();
    const id = parseInt(req.params.id);
    const updatedUser = req.body; // Antag att det uppdaterade användarobjektet skickas i förfråganens kropp
    connection.query('UPDATE users SET ? WHERE id = ?', [updatedUser, id], (err, result) => {
      connection.end(); // Avsluta anslutningen efter användning
      if (err) {
        console.error('Error updating user: ' + err.stack);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
      if (result.affectedRows === 0) {
        res.status(404).json({ error: 'User not found' });
        return;
      }
      res.status(200).json({ message: 'User updated successfully' });
    });
  } catch (error) {
    console.error('Database connection error: ' + error.stack);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { name, password } = req.body;

    const connection = await getDBConnection();

    connection.query('SELECT * FROM users WHERE name = ?', [name], async (err, results) => {
      if (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ error: 'Internal server error' });
        return;
      }
      if (results.length === 0) {
        res.status(401).json({ error: 'Invalid username or password' });
        return;
      }

      const user = results[0];

      if (!user.hashed_password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        connection.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id], (err) => {
          if (err) {
            console.error('Error updating password:', err);
            res.status(500).json({ error: 'Internal server error' });
            return;
          }
          const token = generateToken(user.id);
          res.status(200).json({ token });
        });
      } else {
        const passwordMatch = await bcrypt.compare(password, user.hashed_password);
        if (!passwordMatch) {
          res.status(401).json({ error: 'Invalid username or password' });
          return;
        }
        const token = generateToken(user.id);
        res.status(200).json({ token });
      }
    });
  } catch (error) {
    console.error('Database connection error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Skyddad route som kräver JWT-token för att komma åt
app.get('/protected', verifyToken, (req, res) => {
  res.status(200).json({ message: 'Protected route accessed successfully' });
});



app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
