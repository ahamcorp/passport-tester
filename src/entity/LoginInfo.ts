import {Entity, PrimaryGeneratedColumn, PrimaryColumn, Column} from "typeorm";

@Entity()
export class LoginInfo {

    @PrimaryColumn({unique:true})
    username: string;

    @Column({unique: true})
    userID: number;

    @Column()
    salt: string;

    @Column()
    hash: string;

}
