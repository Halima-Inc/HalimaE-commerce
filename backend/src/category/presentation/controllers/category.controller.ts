import {
    Controller,
    Delete,
    Body,
    HttpCode,
    HttpStatus,
    Param,
    Patch,
    Query,
    Get,
    Post,
    UseGuards,
} from '@nestjs/common';
import {
    ApiTags,
    ApiOperation,
    ApiParam,
    ApiQuery,
    ApiBearerAuth,
    ApiBody,
    ApiExtraModels,
} from '@nestjs/swagger';
import {
    ApiStandardResponse,
    ApiStandardErrorResponse,
    ApiStandardNoContentResponse,
} from '../../../common/swagger/api-response.decorator';
import {
    CreateCategoryDto,
    ResponseCategoriesFilteredDto,
    ResponseCategoryDto,
    UpdateCategoryDto,
} from '../dto';
import {
    CreateCategoryCommand,
    DeleteCategoryCommand,
    GetCategoryByIdQuery,
    GetCategoryBySlugQuery,
    ListCategoriesQuery,
    UpdateCategoryCommand,
    CreateCategoryHandler,
    DeleteCategoryHandler,
    GetCategoryByIdHandler,
    GetCategoryBySlugHandler,
    ListCategoriesHandler,
    UpdateCategoryHandler,
} from '../../application';
import {
    JwtAccessTokenGuard,
    RequiredRoles,
    RolesGuard,
} from '../../../auth/presentation';

@ApiTags('categories')
@ApiExtraModels(
    ResponseCategoriesFilteredDto,
    ResponseCategoryDto,
    CreateCategoryDto,
    UpdateCategoryDto,
)
@Controller('categories')
export class CategoryController {
    constructor(
        private readonly listCategoriesHandler: ListCategoriesHandler,
        private readonly getCategoryByIdHandler: GetCategoryByIdHandler,
        private readonly getCategoryBySlugHandler: GetCategoryBySlugHandler,
        private readonly createCategoryHandler: CreateCategoryHandler,
        private readonly updateCategoryHandler: UpdateCategoryHandler,
        private readonly deleteCategoryHandler: DeleteCategoryHandler,
    ) {}

    @Get()
    @ApiOperation({
        summary: 'Get all categories with pagination and filtering',
        description:
            'Retrieve a paginated list of categories with optional search and sorting',
    })
    @ApiQuery({
        name: 'page',
        required: false,
        type: Number,
        description: 'Page number (starts from 1)',
        example: 1,
    })
    @ApiQuery({
        name: 'limit',
        required: false,
        type: Number,
        description: 'Number of items per page',
        example: 10,
    })
    @ApiQuery({
        name: 'orderBy',
        required: false,
        type: String,
        description: 'Field to order by',
        example: 'name',
    })
    @ApiQuery({
        name: 'orderDirection',
        required: false,
        type: String,
        description: 'Order direction (asc/desc)',
        example: 'asc',
    })
    @ApiQuery({
        name: 'search',
        required: false,
        type: String,
        description: 'Search term for category name',
        example: 'electronics',
    })
    @ApiStandardResponse(
        ResponseCategoriesFilteredDto,
        'Categories retrieved successfully',
        200,
        'Request completed successfully',
    )
    @ApiStandardErrorResponse(404, 'Not Found', 'No categories found')
    getAllCategories(
        @Query('page') page?: number,
        @Query('limit') limit?: number,
        @Query('orderBy') orderBy?: string,
        @Query('orderDirection') orderDirection?: string,
        @Query('search') search?: string,
    ): Promise<ResponseCategoriesFilteredDto> {
        const safePage =
            typeof page === 'number' && Number.isFinite(page) && page > 0
                ? Math.floor(page)
                : 1;
        const safeLimit =
            typeof limit === 'number' && Number.isFinite(limit) && limit > 0
                ? Math.min(Math.floor(limit), 100)
                : 10;

        return this.listCategoriesHandler.execute({
            page: safePage,
            limit: safeLimit,
            orderBy: orderBy === 'slug' ? 'slug' : 'name',
            orderDirection: orderDirection === 'desc' ? 'desc' : 'asc',
            search: search?.trim() || undefined,
        } satisfies ListCategoriesQuery);
    }

    @Get(':id')
    @ApiOperation({
        summary: 'Get category by ID',
        description: 'Retrieve a single category by its unique identifier',
    })
    @ApiParam({
        name: 'id',
        description: 'Category ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardResponse(
        ResponseCategoryDto,
        'Category retrieved successfully',
        200,
        'Request completed successfully',
    )
    @ApiStandardErrorResponse(404, 'Not Found', 'Category not found')
    getCategoryById(@Param('id') id: string): Promise<ResponseCategoryDto> {
        return this.getCategoryByIdHandler.execute(
            new GetCategoryByIdQuery(id),
        );
    }

    @Get('slug/:slug')
    @ApiOperation({
        summary: 'Get category by slug',
        description: 'Retrieve a single category by its URL-friendly slug',
    })
    @ApiParam({
        name: 'slug',
        description: 'Category slug',
        example: 'electronics',
    })
    @ApiStandardResponse(
        ResponseCategoryDto,
        'Category retrieved successfully',
        200,
        'Request completed successfully',
    )
    @ApiStandardErrorResponse(404, 'Not Found', 'Category not found')
    getCategoryBySlug(
        @Param('slug') slug: string,
    ): Promise<ResponseCategoryDto> {
        return this.getCategoryBySlugHandler.execute(
            new GetCategoryBySlugQuery(slug),
        );
    }

    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @Post()
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({
        summary: 'Create a new category',
        description: 'Create a new category (Admin/Employee only)',
    })
    @ApiBody({ type: CreateCategoryDto })
    @ApiStandardResponse(
        ResponseCategoryDto,
        'Category created successfully',
        201,
        'Resource created successfully',
    )
    @ApiStandardErrorResponse(400, 'Validation failed', 'Validation failed')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @HttpCode(HttpStatus.CREATED)
    createCategory(
        @Body() createCategoryDto: CreateCategoryDto,
    ): Promise<ResponseCategoryDto> {
        return this.createCategoryHandler.execute(
            new CreateCategoryCommand(createCategoryDto),
        );
    }

    @RequiredRoles('admin', 'employee')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @Patch(':id')
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({
        summary: 'Update a category',
        description: 'Update an existing category (Admin/Employee only)',
    })
    @ApiParam({
        name: 'id',
        description: 'Category ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiBody({ type: UpdateCategoryDto })
    @ApiStandardResponse(
        ResponseCategoryDto,
        'Category updated successfully',
        200,
        'Resource updated successfully',
    )
    @ApiStandardErrorResponse(400, 'Validation failed', 'Validation failed')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Not Found', 'Category not found')
    @HttpCode(HttpStatus.OK)
    updateCategory(
        @Param('id') id: string,
        @Body() updateCategoryDto: UpdateCategoryDto,
    ): Promise<ResponseCategoryDto> {
        return this.updateCategoryHandler.execute(
            new UpdateCategoryCommand(id, updateCategoryDto),
        );
    }

    // Admin-only routes

    @Delete(':id')
    @RequiredRoles('admin')
    @UseGuards(JwtAccessTokenGuard, RolesGuard)
    @ApiBearerAuth('JWT-auth')
    @ApiOperation({
        summary: 'Delete a category (Admin)',
        description: 'Delete an existing category (Admin only)',
    })
    @ApiParam({
        name: 'id',
        description: 'Category ID',
        example: '123e4567-e89b-12d3-a456-426614174000',
    })
    @ApiStandardNoContentResponse('Category deleted successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Not Found', 'Category not found')
    @HttpCode(HttpStatus.NO_CONTENT)
    deleteCategory(@Param('id') id: string) {
        return this.deleteCategoryHandler.execute(
            new DeleteCategoryCommand(id),
        );
    }
}
