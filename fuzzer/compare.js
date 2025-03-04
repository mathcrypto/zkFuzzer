const fs = require('fs');

function areJsonFilesEqual(filePath1, filePath2) {
    const json1 = JSON.parse(fs.readFileSync(filePath1, 'utf8'));
    const json2 = JSON.parse(fs.readFileSync(filePath2, 'utf8'));

    return JSON.stringify(json1) === JSON.stringify(json2);
}

// Example Usage
const file1 = 'build/public.json';
const file2 = 'build/mutated-public.json';

if (areJsonFilesEqual(file1, file2)) {
    console.log('✅ The JSON files are exactly the same.');
} else {
    console.log('❌ The JSON files are different.');
}
