const { PrismaClient } = require('@prisma/client');

(async () => {
  const prisma = new PrismaClient();
  try {
    await prisma.$connect();
    const counts = {};
    counts.dashboardRevenueSnapshot = await prisma.dashboardRevenueSnapshot.count();
    counts.outboxEvent = await prisma.outboxEvent.count();
    counts.ordersByStatus = await prisma.ordersByStatus.count();
    counts.bestSellingProduct = await prisma.bestSellingProduct.count();
    counts.lowStockProduct = await prisma.lowStockProduct.count();
    counts.ordersByLocation = await prisma.ordersByLocation.count();
    counts.orderStatistics = await prisma.orderStatistics.count();
    counts.customerCounters = await prisma.customerCounters.count();
    counts.productsByCategory = await prisma.productsByCategory.count();

    console.log('Projection row counts:');
    for (const k of Object.keys(counts)) {
      console.log(` - ${k}: ${counts[k]}`);
    }
  } catch (err) {
    console.error('Failed to inspect projections:', err);
    process.exitCode = 2;
  } finally {
    await prisma.$disconnect();
  }
})();
