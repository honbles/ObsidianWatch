FROM node:20-alpine AS builder
WORKDIR /app
# Dependencies are installed in their own directory so nothing copied from the build context (a
# node_modules left on the host, with or without .dockerignore) can replace them.
COPY package*.json /deps/
RUN cd /deps && npm ci --include=dev --no-audit --no-fund && test -x /deps/node_modules/.bin/vite
COPY . .
RUN rm -rf node_modules && ln -s /deps/node_modules node_modules && npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh && mkdir -p /etc/nginx/certs
EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint.sh"]
