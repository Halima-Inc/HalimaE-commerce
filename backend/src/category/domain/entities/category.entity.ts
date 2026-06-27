export type CategoryRecord = {
    id: string;
    name: string;
    slug: string;
    parentId: string | null;
    parent?: CategoryRecord | null;
};

export class Category {
    constructor(
        public readonly id: string,
        public readonly name: string,
        public readonly slug: string,
        public readonly parentId: string | null,
        public readonly parent: Category | null = null,
    ) {}

    static create(record: CategoryRecord): Category {
        return new Category(
            record.id,
            record.name,
            record.slug,
            record.parentId,
            record.parent ? Category.create(record.parent) : null,
        );
    }

    hasParent(): boolean {
        return this.parentId !== null;
    }

    isRoot(): boolean {
        return this.parentId === null;
    }

    canBeParentOf(child: Category): boolean {
        return this.id !== child.id;
    }
}
