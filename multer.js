const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, './public/images'));
    },

    filename: function (req, file, cb) {
        const name = Math.round(Math.random() * 16).toString(16) + '-' + file.originalname;
        cb(null, name);
    }
});


const upload = multer({ 
    storage: storage, 
});

module.exports = upload;
