# Node.js 20 Alpine image ব্যবহার করছি
FROM node:20-alpine

# ওয়ার্কিং ডিরেক্টরি সেট করা
WORKDIR /app

# প্যাকেজ ফাইল কপি করা
COPY package*.json ./

# ডিপেন্ডেন্সি ইনস্টল করা (প্রোডাকশনের জন্য)
RUN npm install --omit=dev

# বাকি সব সোর্স কোড কপি করা
COPY . .

# পোর্ট এক্সপোজ করা
EXPOSE 3000

# সার্ভার রান করা
CMD ["node", "server.js"]