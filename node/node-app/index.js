import express from 'express';
import authGatekeeper from './middleware/authGatekeeper.js';

const app = express();
app.use(express.json());

app.use(authGatekeeper("http://localhost:8082/gatekeeper"));

app.get('/', (req, res) => {
  res.json({
    message: "Hello World",
    realm: req.realm || null,
    validation: req.validation || null,
  });
});

const questionHandler = (req, res) => {
  res.json({
    message: "This is a validated /question endpoint.",
    token_payload: req.token_payload || null,
    validation: req.validation || null,
  });
};

app.get('/question', questionHandler);
app.post('/question', questionHandler);

app.listen(8000, () => {
  console.log("Server running on http://localhost:8000");
});