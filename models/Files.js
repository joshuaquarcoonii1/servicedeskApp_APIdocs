const mongoose = require('mongoose')


const fileSchema = new mongoose.Schema({
    originalName: String,
    mimeType: String,
    size: Number,
    filePath: String, // Optional: If storing file paths instead of binary data
  });
  
  // Define a model
  const File = mongoose.model('File', fileSchema);
  module.exports = File;