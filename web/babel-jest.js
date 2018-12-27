const babeljest = require('babel-jest');
const babelOptions = {
  "presets": [["@babel/preset-env", {"modules": false}], "@babel/preset-react"],
  "env": {
    "test": {
      "presets": [["@babel/preset-env"], "@babel/preset-react"]
    }
  },
  "plugins": [
    "@babel/plugin-proposal-class-properties",
    "@babel/plugin-proposal-object-rest-spread",
    "@babel/plugin-syntax-dynamic-import"
  ]
}

module.exports = babeljest.createTransformer(babelOptions);