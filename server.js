// server.js
const express = require('express');
const bodyParser = require('body-parser');
const routes = require('./routes');
const app = express();

app.use(bodyParser.json()); 
  // Routes
app.use('/api', routes);




const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
