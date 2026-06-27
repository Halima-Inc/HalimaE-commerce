import {
    Body,
    Controller,
    Delete,
    Get,
    HttpCode,
    HttpStatus,
    Param,
    Patch,
    Post,
    UseGuards,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiExtraModels,
    ApiOperation,
    ApiTags,
} from '@nestjs/swagger';
import { RequiredPermissions } from '../decorators';
import { JwtAccessTokenGuard, PermissionsGuard } from '../guards';
import {
    CreateRoleCommand,
    DeleteRoleCommand,
    UpdateRolePermissionsCommand,
} from '../../application/commands';
import {
    CreateRoleHandler,
    DeleteRoleHandler,
    GetRolesHandler,
    UpdateRolePermissionsHandler,
} from '../../application/handlers';
import {
    ApiStandardErrorResponse,
    ApiStandardNoContentResponse,
    ApiStandardResponse,
} from '../../../common/swagger/api-response.decorator';
import {
    CreateRoleRequestDto,
    RoleResponseDto,
    UpdateRolePermissionsRequestDto,
} from '../dtos';

@ApiTags('roles')
@ApiBearerAuth('JWT-auth')
@ApiExtraModels(
    CreateRoleRequestDto,
    UpdateRolePermissionsRequestDto,
    RoleResponseDto,
)
@UseGuards(JwtAccessTokenGuard, PermissionsGuard)
@Controller('auth/roles')
export class RolesController {
    constructor(
        private readonly getRolesHandler: GetRolesHandler,
        private readonly createRoleHandler: CreateRoleHandler,
        private readonly updateRolePermissionsHandler: UpdateRolePermissionsHandler,
        private readonly deleteRoleHandler: DeleteRoleHandler,
    ) {}

    @Get()
    @RequiredPermissions('roles.read')
    @ApiOperation({ summary: 'List editable roles' })
    @ApiStandardResponse(Object, 'Editable roles retrieved successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized')
    @ApiStandardErrorResponse(403, 'Forbidden')
    async findAll() {
        return this.getRolesHandler.execute();
    }

    @Post()
    @RequiredPermissions('roles.create')
    @ApiOperation({ summary: 'Create role' })
    @ApiStandardResponse(RoleResponseDto, 'Role created successfully', 201)
    @ApiStandardErrorResponse(400, 'Invalid role payload')
    @ApiStandardErrorResponse(401, 'Unauthorized')
    @ApiStandardErrorResponse(403, 'Forbidden')
    @ApiStandardErrorResponse(404, 'Permission not found')
    @ApiStandardErrorResponse(409, 'Role already exists')
    @HttpCode(HttpStatus.CREATED)
    async create(@Body() body: CreateRoleRequestDto) {
        return this.createRoleHandler.execute(
            new CreateRoleCommand(body.name, body.permissions ?? []),
        );
    }

    @Patch(':id/permissions')
    @RequiredPermissions('roles.update')
    @ApiOperation({ summary: 'Update role permissions' })
    @ApiStandardResponse(
        RoleResponseDto,
        'Role permissions updated successfully',
    )
    @ApiStandardErrorResponse(400, 'Invalid role permissions payload')
    @ApiStandardErrorResponse(401, 'Unauthorized')
    @ApiStandardErrorResponse(403, 'Forbidden')
    @ApiStandardErrorResponse(404, 'Role or permission not found')
    async updatePermissions(
        @Param('id') roleId: string,
        @Body() body: UpdateRolePermissionsRequestDto,
    ) {
        return this.updateRolePermissionsHandler.execute(
            new UpdateRolePermissionsCommand(roleId, body.permissions ?? []),
        );
    }

    @Delete(':id')
    @RequiredPermissions('roles.delete')
    @ApiOperation({ summary: 'Delete role' })
    @ApiStandardNoContentResponse('Role deleted successfully')
    @ApiStandardErrorResponse(401, 'Unauthorized')
    @ApiStandardErrorResponse(403, 'Forbidden')
    @ApiStandardErrorResponse(404, 'Role not found')
    @HttpCode(HttpStatus.NO_CONTENT)
    async delete(@Param('id') roleId: string) {
        await this.deleteRoleHandler.execute(new DeleteRoleCommand(roleId));
    }
}
