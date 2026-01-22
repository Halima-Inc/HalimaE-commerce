import {
    Controller,
    Get,
    Post,
    Body,
    Patch,
    Param,
    Delete,
    UploadedFiles,
    UseInterceptors,
    UseGuards,
    Query,
    BadRequestException,
    HttpCode,
    HttpStatus,
    Put,
    UploadedFile,
} from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth, ApiConsumes, ApiBody, ApiExtraModels } from '@nestjs/swagger';
import { ApiStandardResponse, ApiStandardErrorResponse, ApiStandardNoContentResponse } from '../../common/swagger/api-response.decorator';
import { ProductService } from './product.service';
import {
    CreateProductDto,
    FilterProductDto,
    ProductImageDto,
    ProductVariantDto,
    ResponseProductDto,
    ResponseVariantDto,
    UpdateProductDto,
    UpdateVariantDto,
} from './dto';
import { FileInterceptor, FilesInterceptor } from '@nestjs/platform-express';
import { Roles } from '../auth/user-auth/decorators';
import { JwtUserGuard, RolesGuard } from '../auth/user-auth/guards';
import { ProductVariantService } from './product-variant.service';
import { ProductImageService } from './product-image.service';
import { ParseJsonPipe } from '../utils/parse-json.pipe';
import { ResponseProductFilteredDto } from './dto/product/response-product-filtered.dto';
import { VariantPriceDto } from './dto/variant/variant-price.dto';
import { VariantInventoryDto } from './dto/variant/variant-inventory.dto';

@ApiTags('products')
@ApiExtraModels(
    CreateProductDto, 
    UpdateProductDto, 
    ResponseProductDto,
    ResponseProductFilteredDto,
    FilterProductDto,
    ProductVariantDto,
    UpdateVariantDto,
    ResponseVariantDto,
    ProductImageDto,
    VariantPriceDto,
    VariantInventoryDto
)
@Controller('products')
export class ProductController {
    constructor(
        private readonly productService: ProductService,
        private readonly productVariantService: ProductVariantService,
        private readonly productImageService: ProductImageService
    ) { }

    @Get()
    @ApiOperation({ summary: 'Get all products with filters', description: 'Retrieve a paginated list of products with optional filters for name, category, status, and price range' })
    @ApiStandardResponse(ResponseProductFilteredDto, 'Products retrieved successfully')
    @ApiStandardErrorResponse(400, 'Invalid filter parameters', 'Invalid filter parameters provided')
    async getProducts(
        @Query() filters: FilterProductDto
    ) {
        return this.productService.findAll(filters);
    }

    @Get(':id')
    @ApiOperation({ summary: 'Get product by ID', description: 'Retrieve detailed information about a specific product' })
    @ApiStandardResponse(ResponseProductDto, 'Product retrieved successfully')
    @ApiStandardErrorResponse(404, 'Product not found', 'Product with the given ID was not found')
    async getProductById(@Param('id') id: string): Promise<ResponseProductDto> {
        return this.productService.findById(id);
    }

    @Get(':id/variants')
    @ApiOperation({ summary: 'Get product variants', description: 'Retrieve all variants (sizes, colors, etc.) for a specific product' })
    @ApiStandardResponse(ResponseVariantDto, 'Variants retrieved successfully')
    @ApiStandardErrorResponse(404, 'Product not found', 'Product with the given ID was not found')
    async getProductVariants(@Param('id') id: string): Promise<ResponseVariantDto[]> {
        return this.productVariantService.getVariantsByProductId(id);
    }

    @Get(':id/images')
    @ApiOperation({ summary: 'Get product images', description: 'Retrieve all images for a specific product' })
    @ApiStandardResponse(ProductImageDto, 'Images retrieved successfully')
    @ApiStandardErrorResponse(404, 'Product not found', 'Product with the given ID was not found')
    async getProductImages(@Param('id') id: string) {
        return this.productImageService.getImagesByProductId(id);
    }


    @Post()
    @ApiOperation({ summary: 'Create new product (Admin/Employee)', description: 'Create a new product with its variants. Requires admin or employee role.' })
    @ApiBearerAuth()
    @ApiStandardResponse(ResponseProductDto, 'Product created successfully', 201)
    @ApiStandardErrorResponse(400, 'Invalid product data', 'Validation failed for product creation')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Category not found', 'The specified category does not exist')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @HttpCode(HttpStatus.CREATED)
    async createProduct(
        @Body() productDto: CreateProductDto,
    ): Promise<ResponseProductDto | null> {
        return this.productService.create(productDto);
    }

    @Post(':id/images')
    @ApiOperation({ summary: 'Upload product images (Admin/Employee)', description: 'Upload multiple images for a product (max 10). Images are sent as multipart/form-data with optional metadata.' })
    @ApiBearerAuth()
    @ApiConsumes('multipart/form-data')
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                images: {
                    type: 'array',
                    items: {
                        type: 'string',
                        format: 'binary',
                    },
                    description: 'Image files to upload (max 10)',
                },
                imagesMeta: {
                    type: 'string',
                    description: 'JSON string array of image metadata (alt text, sort order)',
                    example: JSON.stringify([{ alt: 'Product front view', sort: 1 }])
                }
            },
            required: ['images']
        },
    })
    @ApiStandardResponse(ProductImageDto, 'Images uploaded successfully', 201)
    @ApiStandardErrorResponse(400, 'Invalid request', 'At least one image file must be uploaded or metadata count mismatch')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Product not found', 'Product with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @UseInterceptors(FilesInterceptor('images', 10))
    @HttpCode(HttpStatus.CREATED)
    async addImages(
        @Param('id') id: string,
        @Body('imagesMeta', new ParseJsonPipe())
        productImagesDto: ProductImageDto[],
        @UploadedFiles() images: Array<Express.Multer.File>
    ) {
        // validate metadata length matches images length if metadata provided
        if (!images || images.length === 0) {
            throw new BadRequestException('At least one image file must be uploaded.');
        }
        // If productImagesDto has content, its length must match the number of files.
        if (productImagesDto && productImagesDto.length > 0 && productImagesDto.length !== images.length) {
            throw new BadRequestException('The number of image metadata objects does not match the number of uploaded files.');
        }

        return this.productImageService.createMany(id, productImagesDto, images);
    }

    @Post(':id/variants')
    @ApiOperation({ summary: 'Add product variant (Admin/Employee)', description: 'Add a new variant (size, color, etc.) to an existing product' })
    @ApiBearerAuth()
    @ApiStandardResponse(ResponseVariantDto, 'Variant created successfully', 201)
    @ApiStandardErrorResponse(400, 'Invalid variant data', 'Validation failed for variant creation')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Product not found', 'Product with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @HttpCode(HttpStatus.CREATED)
    async addVariant(
        @Param('id') id: string,
        @Body() variantDto: ProductVariantDto
    ): Promise<ResponseVariantDto> {
        return this.productVariantService.create(id, variantDto);
    }

    @Patch(':id')
    @ApiOperation({ summary: 'Update product (Admin/Employee)', description: 'Update product information (name, description, status, etc.)' })
    @ApiBearerAuth()
    @ApiStandardResponse(ResponseProductDto, 'Product updated successfully')
    @ApiStandardErrorResponse(400, 'Invalid update data', 'Validation failed for product update')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Product not found', 'Product with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @HttpCode(HttpStatus.OK)
    async updateProduct(
        @Param('id') id: string,
        @Body() updateProductDto: UpdateProductDto,
    ): Promise<ResponseProductDto> {
        return this.productService.update(id, updateProductDto);
    }

    @Patch(':id/variants/:variantId')
    @ApiOperation({ summary: 'Update product variant (Admin/Employee)', description: 'Update a specific variant of a product' })
    @ApiBearerAuth()
    @ApiStandardResponse(ResponseVariantDto, 'Variant updated successfully')
    @ApiStandardErrorResponse(400, 'Invalid update data', 'Validation failed for variant update')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Variant not found', 'Product or variant with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @HttpCode(HttpStatus.OK)
    async updateVariant(
        @Param('id') id: string,
        @Param('variantId') variantId: string,
        @Body() variantDto: UpdateVariantDto,
    ): Promise<ResponseVariantDto> {
        return this.productVariantService.update(id, variantId, variantDto);
    }


    @Put(':id/images/:imageId')
    @ApiOperation({ summary: 'Replace product image (Admin/Employee)', description: 'Replace an existing product image with a new one' })
    @ApiBearerAuth()
    @ApiConsumes('multipart/form-data')
    @ApiBody({
        schema: {
            type: 'object',
            properties: {
                image: {
                    type: 'string',
                    format: 'binary',
                    description: 'New image file to replace the existing one',
                }
            },
            required: ['image']
        },
    })
    @ApiStandardResponse(ProductImageDto, 'Image replaced successfully')
    @ApiStandardErrorResponse(400, 'Invalid image file', 'Image file is required')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Image not found', 'Product or image with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @UseInterceptors(FileInterceptor('image'))
    @HttpCode(HttpStatus.OK)
    async replaceImage(
        @Param('id') id: string,
        @Param('imageId') imageId: string,
        @UploadedFile() image: Express.Multer.File,
    ) {
        return this.productImageService.replace(id, imageId, image);
    }

    @Delete(':id')
    @ApiOperation({ summary: 'Delete product (Admin/Employee)', description: 'Delete a product and all its associated variants and images' })
    @ApiBearerAuth()
    @ApiStandardNoContentResponse('Product deleted successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Product not found', 'Product with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @HttpCode(HttpStatus.NO_CONTENT)
    async removeProduct(@Param('id') id: string) {
        await this.productService.remove(id);
    }


    @Delete(':id/variants/:variantId')
    @ApiOperation({ summary: 'Delete product variant (Admin/Employee)', description: 'Delete a specific variant of a product' })
    @ApiBearerAuth()
    @ApiStandardNoContentResponse('Variant deleted successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Variant not found', 'Product or variant with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @HttpCode(HttpStatus.NO_CONTENT)
    async removeVariant(@Param('id') id: string, @Param('variantId') variantId: string) {
        await this.productVariantService.delete(id, variantId);
    }


    @Delete(':id/images/:imageId')
    @ApiOperation({ summary: 'Delete product image (Admin/Employee)', description: 'Delete a specific image of a product' })
    @ApiBearerAuth()
    @ApiStandardNoContentResponse('Image deleted successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized', 'Authentication required')
    @ApiStandardErrorResponse(403, 'Forbidden', 'Insufficient permissions')
    @ApiStandardErrorResponse(404, 'Image not found', 'Product or image with the given ID was not found')
    @Roles('admin', 'employee')
    @UseGuards(JwtUserGuard, RolesGuard)
    @HttpCode(HttpStatus.NO_CONTENT)
    async removeImage(@Param('id') id: string, @Param('imageId') imageId: string) {
        await this.productImageService.delete(id, imageId);
    }
}