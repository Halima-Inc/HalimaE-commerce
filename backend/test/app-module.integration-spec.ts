import { Test, TestingModule } from '@nestjs/testing';
import { AppModule } from '../src/app.module';

describe('AppModule dependency graph', () => {
    let moduleFixture: TestingModule;

    afterEach(async () => {
        await moduleFixture?.close();
    });

    it('compiles the application module', async () => {
        moduleFixture = await Test.createTestingModule({
            imports: [AppModule],
        }).compile();

        expect(moduleFixture).toBeDefined();
    });
});
