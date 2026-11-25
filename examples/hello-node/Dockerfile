# No dependencies to install: copy the app and run it as the image's
# unprivileged "node" user.
FROM node:24.22.1-alpine3.23@sha256:0468540aa58203ff9e40c2aab3907c52644ab818af6176b1c70a026137dc92a2
WORKDIR /app
COPY package.json server.js ./
ENV NODE_ENV=production
USER node
EXPOSE 8080
CMD ["node", "server.js"]
