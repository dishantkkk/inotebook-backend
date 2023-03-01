const connectToMongo = require('./db')
const cors = require('cors')
const express = require('express')

connectToMongo();

const app = express()
const port = 5000

app.use(cors())
app.use(express.json())

//available routes
app.use('/api/auth', require('./routes/auth'))
app.use('/api/notes', require('./routes/notes'))

app.listen(port, () => {
  console.log(`iNoteBook backend app listening on port ${port}`)
})