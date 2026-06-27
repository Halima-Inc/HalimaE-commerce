-- CreateTable
CREATE TABLE "dashboard_revenue_snapshots" (
    "id" SERIAL NOT NULL,
    "date" TIMESTAMP(3) NOT NULL,
    "revenue" DECIMAL(12,2) NOT NULL DEFAULT 0,
    "orders" INTEGER NOT NULL DEFAULT 0,
    "itemsSold" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "dashboard_revenue_snapshots_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dashboard_orders_by_status" (
    "id" SERIAL NOT NULL,
    "status" "ORDERSTATUS" NOT NULL,
    "date" TIMESTAMP(3) NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "dashboard_orders_by_status_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dashboard_best_selling_products" (
    "id" SERIAL NOT NULL,
    "productId" UUID NOT NULL,
    "periodStart" TIMESTAMP(3) NOT NULL,
    "periodEnd" TIMESTAMP(3) NOT NULL,
    "qtySold" INTEGER NOT NULL DEFAULT 0,
    "revenue" DECIMAL(12,2) NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dashboard_best_selling_products_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dashboard_low_stock_products" (
    "id" SERIAL NOT NULL,
    "variantId" UUID NOT NULL,
    "productId" UUID NOT NULL,
    "stockOnHand" INTEGER NOT NULL,
    "lowStockThreshold" INTEGER NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dashboard_low_stock_products_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dashboard_orders_by_location" (
    "id" SERIAL NOT NULL,
    "location" TEXT NOT NULL,
    "date" TIMESTAMP(3) NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 0,
    "revenue" DECIMAL(12,2) NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dashboard_orders_by_location_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dashboard_order_statistics" (
    "id" SERIAL NOT NULL,
    "key" TEXT NOT NULL,
    "intValue" INTEGER,
    "decValue" DECIMAL(12,2),
    "jsonValue" JSONB,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dashboard_order_statistics_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dashboard_customer_counters" (
    "id" SERIAL NOT NULL,
    "customerId" UUID NOT NULL,
    "orders" INTEGER NOT NULL DEFAULT 0,
    "lifetimeValue" DECIMAL(12,2) NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dashboard_customer_counters_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dashboard_products_by_category" (
    "id" SERIAL NOT NULL,
    "categoryId" UUID NOT NULL,
    "periodStart" TIMESTAMP(3) NOT NULL,
    "periodEnd" TIMESTAMP(3) NOT NULL,
    "qtySold" INTEGER NOT NULL DEFAULT 0,
    "revenue" DECIMAL(12,2) NOT NULL DEFAULT 0,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dashboard_products_by_category_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_revenue_snapshots_date_key" ON "dashboard_revenue_snapshots"("date");

-- CreateIndex
CREATE INDEX "dashboard_revenue_snapshots_date_idx" ON "dashboard_revenue_snapshots"("date");

-- CreateIndex
CREATE INDEX "dashboard_orders_by_status_date_idx" ON "dashboard_orders_by_status"("date");

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_orders_by_status_status_date_key" ON "dashboard_orders_by_status"("status", "date");

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_best_selling_products_productId_periodStart_key" ON "dashboard_best_selling_products"("productId", "periodStart");

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_low_stock_products_variantId_key" ON "dashboard_low_stock_products"("variantId");

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_orders_by_location_location_date_key" ON "dashboard_orders_by_location"("location", "date");

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_order_statistics_key_key" ON "dashboard_order_statistics"("key");

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_customer_counters_customerId_key" ON "dashboard_customer_counters"("customerId");

-- CreateIndex
CREATE UNIQUE INDEX "dashboard_products_by_category_categoryId_periodStart_key" ON "dashboard_products_by_category"("categoryId", "periodStart");
